//! Remote VM database backed by archive node JSON-RPC.
//!
//! Like a lazy filing cabinet: looks up state on first access, caches locally.
//! Implements the LEVM `Database` trait so it plugs directly into
//! `GeneralizedDatabase` and `ReplayEngine`.

use std::collections::VecDeque;
use std::hash::Hash;
use std::sync::RwLock;

use bytes::Bytes;
use ethrex_common::{
    Address, H256, U256,
    types::{AccountState, ChainConfig, Code, CodeMetadata},
};
use ethrex_levm::{db::Database, errors::DatabaseError};
use rustc_hash::FxHashMap;

use crate::autopsy::rpc_client::{EthRpcClient, RpcConfig};

/// Default cache capacity per category.
const DEFAULT_CACHE_CAPACITY: usize = 10_000;

/// Capacity-bounded cache with FIFO eviction.
///
/// When the cache reaches `max_entries`, the oldest entry (by insertion order)
/// is evicted. This prevents unbounded memory growth on large traces.
struct BoundedCache<K: Eq + Hash + Clone, V> {
    map: FxHashMap<K, V>,
    order: VecDeque<K>,
    max_entries: usize,
}

impl<K: Eq + Hash + Clone, V> BoundedCache<K, V> {
    fn new(max_entries: usize) -> Self {
        Self {
            map: FxHashMap::default(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    fn insert(&mut self, key: K, value: V) {
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.map.entry(key.clone()) {
            e.insert(value);
            return;
        }
        // Evict oldest if at capacity
        if self.map.len() >= self.max_entries
            && let Some(oldest) = self.order.pop_front()
        {
            self.map.remove(&oldest);
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Database implementation that fetches state from an Ethereum archive node.
///
/// Caches all fetched data in memory — repeated lookups for the same address
/// or slot are served from cache without network calls.
pub struct RemoteVmDatabase {
    client: EthRpcClient,
    chain_config: ChainConfig,
    account_cache: RwLock<BoundedCache<Address, AccountState>>,
    storage_cache: RwLock<BoundedCache<(Address, H256), U256>>,
    code_cache: RwLock<BoundedCache<H256, Code>>,
    code_metadata_cache: RwLock<BoundedCache<H256, CodeMetadata>>,
    block_hash_cache: RwLock<BoundedCache<u64, H256>>,
}

impl RemoteVmDatabase {
    /// Create a new remote database targeting a specific block on a chain.
    ///
    /// `chain_id` is used to build a `ChainConfig`. For mainnet (chain_id=1),
    /// all fork blocks are set to activated (0/Some(0)).
    pub fn new(client: EthRpcClient, chain_id: u64) -> Self {
        Self {
            client,
            chain_config: mainnet_chain_config(chain_id),
            account_cache: RwLock::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)),
            storage_cache: RwLock::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY * 10)),
            code_cache: RwLock::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)),
            code_metadata_cache: RwLock::new(BoundedCache::new(DEFAULT_CACHE_CAPACITY)),
            block_hash_cache: RwLock::new(BoundedCache::new(1_000)),
        }
    }

    /// Create from RPC URL, auto-detecting chain_id.
    pub fn from_rpc(url: &str, block_number: u64) -> Result<Self, DatabaseError> {
        let client = EthRpcClient::new(url, block_number);
        let chain_id = client
            .eth_chain_id()
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;
        Ok(Self::new(client, chain_id))
    }

    /// Create from RPC URL with custom config, auto-detecting chain_id.
    pub fn from_rpc_with_config(
        url: &str,
        block_number: u64,
        config: RpcConfig,
    ) -> Result<Self, DatabaseError> {
        let client = EthRpcClient::with_config(url, block_number, config);
        let chain_id = client
            .eth_chain_id()
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;
        Ok(Self::new(client, chain_id))
    }

    /// Access the underlying RPC client.
    pub fn client(&self) -> &EthRpcClient {
        &self.client
    }

    /// Fetch and cache account state + code proactively.
    fn fetch_account(&self, address: Address) -> Result<AccountState, DatabaseError> {
        let balance = self
            .client
            .eth_get_balance(address)
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;
        let nonce = self
            .client
            .eth_get_transaction_count(address)
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;
        let code_bytes = self
            .client
            .eth_get_code(address)
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;

        let code = Code::from_bytecode(Bytes::from(code_bytes));
        let code_hash = code.hash;

        // Proactively cache code and metadata so get_account_code(hash) works
        let metadata = CodeMetadata {
            length: code.bytecode.len() as u64,
        };
        self.code_cache
            .write()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .insert(code_hash, code);
        self.code_metadata_cache
            .write()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .insert(code_hash, metadata);

        let state = AccountState {
            nonce,
            balance,
            storage_root: H256::zero(), // Not available via standard RPC
            code_hash,
        };

        self.account_cache
            .write()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .insert(address, state);

        Ok(state)
    }
}

impl Database for RemoteVmDatabase {
    fn get_account_state(&self, address: Address) -> Result<AccountState, DatabaseError> {
        // Check cache first
        if let Some(state) = self
            .account_cache
            .read()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .get(&address)
            .copied()
        {
            return Ok(state);
        }
        self.fetch_account(address)
    }

    fn get_storage_value(&self, address: Address, key: H256) -> Result<U256, DatabaseError> {
        if let Some(val) = self
            .storage_cache
            .read()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .get(&(address, key))
            .copied()
        {
            return Ok(val);
        }

        let value = self
            .client
            .eth_get_storage_at(address, key)
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;

        self.storage_cache
            .write()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .insert((address, key), value);

        Ok(value)
    }

    fn get_block_hash(&self, block_number: u64) -> Result<H256, DatabaseError> {
        if let Some(hash) = self
            .block_hash_cache
            .read()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .get(&block_number)
            .copied()
        {
            return Ok(hash);
        }

        let header = self
            .client
            .eth_get_block_by_number(block_number)
            .map_err(|e| DatabaseError::Custom(format!("{e}")))?;

        self.block_hash_cache
            .write()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .insert(block_number, header.hash);

        Ok(header.hash)
    }

    fn get_chain_config(&self) -> Result<ChainConfig, DatabaseError> {
        Ok(self.chain_config)
    }

    fn get_account_code(&self, code_hash: H256) -> Result<Code, DatabaseError> {
        // Code is proactively cached during get_account_state().
        // LEVM always calls get_account_state first (see gen_db.rs:load_account).
        self.code_cache
            .read()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| {
                DatabaseError::Custom(format!(
                    "code hash {code_hash:?} not found in cache — call get_account_state first"
                ))
            })
    }

    fn get_code_metadata(&self, code_hash: H256) -> Result<CodeMetadata, DatabaseError> {
        self.code_metadata_cache
            .read()
            .map_err(|e| DatabaseError::Custom(format!("lock: {e}")))?
            .get(&code_hash)
            .copied()
            .ok_or_else(|| {
                DatabaseError::Custom(format!(
                    "code metadata {code_hash:?} not found — call get_account_state first"
                ))
            })
    }
}

/// Build a ChainConfig with all forks activated for the given chain_id.
/// This is correct for mainnet post-Cancun blocks. For other chains,
/// the caller should adjust fork timestamps as needed.
fn mainnet_chain_config(chain_id: u64) -> ChainConfig {
    ChainConfig {
        chain_id,
        homestead_block: Some(0),
        dao_fork_block: Some(0),
        dao_fork_support: true,
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        muir_glacier_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        arrow_glacier_block: Some(0),
        gray_glacier_block: Some(0),
        merge_netsplit_block: Some(0),
        shanghai_time: Some(0),
        cancun_time: Some(0),
        terminal_total_difficulty: Some(0),
        terminal_total_difficulty_passed: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet_chain_config() {
        let config = mainnet_chain_config(1);
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.homestead_block, Some(0));
        assert_eq!(config.cancun_time, Some(0));
        assert!(config.terminal_total_difficulty_passed);
    }

    #[test]
    fn test_mainnet_chain_config_custom_chain() {
        let config = mainnet_chain_config(42161);
        assert_eq!(config.chain_id, 42161);
    }

    #[test]
    fn test_bounded_cache_eviction_at_capacity() {
        let mut cache = BoundedCache::new(3);
        cache.insert(1, "a");
        cache.insert(2, "b");
        cache.insert(3, "c");
        assert_eq!(cache.len(), 3);

        // Insert 4th → evicts key 1 (oldest)
        cache.insert(4, "d");
        assert_eq!(cache.len(), 3);
        assert!(cache.get(&1).is_none(), "oldest entry should be evicted");
        assert_eq!(cache.get(&4), Some(&"d"));
    }

    #[test]
    fn test_bounded_cache_hit_miss_after_eviction() {
        let mut cache = BoundedCache::new(2);
        cache.insert("x", 10);
        cache.insert("y", 20);
        assert_eq!(cache.get(&"x"), Some(&10));

        cache.insert("z", 30); // evicts "x"
        assert!(cache.get(&"x").is_none());
        assert_eq!(cache.get(&"y"), Some(&20));
        assert_eq!(cache.get(&"z"), Some(&30));
    }

    #[test]
    fn test_bounded_cache_update_existing_key() {
        let mut cache = BoundedCache::new(2);
        cache.insert(1, "old");
        cache.insert(1, "new");
        assert_eq!(
            cache.len(),
            1,
            "updating existing key should not grow cache"
        );
        assert_eq!(cache.get(&1), Some(&"new"));
    }

    #[test]
    fn test_bounded_cache_memory_stays_bounded() {
        let mut cache = BoundedCache::new(100);
        for i in 0..500 {
            cache.insert(i, i * 2);
        }
        assert_eq!(cache.len(), 100, "cache should never exceed max_entries");
        // Only the last 100 entries should remain
        assert!(cache.get(&399).is_none());
        assert_eq!(cache.get(&400), Some(&800));
        assert_eq!(cache.get(&499), Some(&998));
    }
}
