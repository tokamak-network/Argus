//! Fixture loading utilities for AI agent test data.
//!
//! Loads `AgentContext` JSON files produced by T3/T4 (manual fixture conversion).
//! Used by T6+ regression tests to validate AI verdict accuracy against known
//! attack and benign transaction samples.
//!
//! # Expected directory layout
//!
//! ```text
//! src/sentinel/ai/test_fixtures/
//! ├── attack/
//! │   ├── balancer_flashloan.json
//! │   ├── bybit_accesscontrol.json
//! │   └── polynetwork_accesscontrol.json
//! └── benign/
//!     ├── uniswap_swap_01.json
//!     └── ...
//! ```

use std::path::Path;

use super::types::AgentContext;

// ── Single file loader ────────────────────────────────────────────────────────

/// Load a single `AgentContext` from a JSON file.
pub fn load_agent_context_from_file(path: &Path) -> Result<AgentContext, serde_json::Error> {
    let content = std::fs::read_to_string(path).map_err(serde_json::Error::io)?;
    serde_json::from_str(&content)
}

// ── Directory loader ──────────────────────────────────────────────────────────

/// Load all `AgentContext` JSON files from a directory (non-recursive).
///
/// Files are sorted by name for deterministic ordering.
/// Non-`.json` files are silently skipped.
pub fn load_agent_contexts_from_dir(
    dir: &Path,
) -> Result<Vec<AgentContext>, Box<dyn std::error::Error>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    entries
        .iter()
        .map(|e| load_agent_context_from_file(&e.path()).map_err(Into::into))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{Address, H256, U256};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::sentinel::ai::types::{AgentContext, CallFrame, CallType};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_id() -> u64 {
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    fn tmp_file(content: &str) -> PathBuf {
        let path = PathBuf::from(format!(
            "/tmp/argus_fix_{}_{}.json",
            std::process::id(),
            unique_id()
        ));
        fs::write(&path, content).unwrap();
        path
    }

    fn tmp_dir() -> PathBuf {
        let path = PathBuf::from(format!(
            "/tmp/argus_fixdir_{}_{}",
            std::process::id(),
            unique_id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn minimal_context() -> AgentContext {
        AgentContext {
            tx_hash: H256::from([1u8; 32]),
            block_number: 21_000_000,
            from: Address::from([0xAA_u8; 20]),
            to: Some(Address::from([0xBB_u8; 20])),
            value_wei: U256::zero(),
            gas_used: 100_000,
            succeeded: true,
            revert_count: 0,
            suspicious_score: 0.3,
            suspicion_reasons: vec![],
            call_graph: vec![],
            storage_mutations: vec![],
            erc20_transfers: vec![],
            eth_transfers: vec![],
            log_events: vec![],
            delegatecalls: vec![],
            contract_creations: vec![],
        }
    }

    #[test]
    fn load_from_file_roundtrip() {
        let ctx = minimal_context();
        let path = tmp_file(&serde_json::to_string(&ctx).unwrap());

        let loaded = load_agent_context_from_file(&path).unwrap();
        assert_eq!(loaded.tx_hash, ctx.tx_hash);
        assert_eq!(loaded.block_number, ctx.block_number);
        assert_eq!(loaded.gas_used, ctx.gas_used);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_from_file_missing_returns_error() {
        let result = load_agent_context_from_file(Path::new("/nonexistent/path/fixture.json"));
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file_malformed_json_returns_error() {
        let path = tmp_file("{ not valid json }");
        assert!(load_agent_context_from_file(&path).is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_from_file_preserves_call_graph() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![CallFrame {
            depth: 1,
            caller: Address::from([0x01_u8; 20]),
            target: Address::from([0x02_u8; 20]),
            value: U256::zero(),
            input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            input_size: 68,
            output_size: 32,
            gas_used: 50_000,
            call_type: CallType::Call,
            reverted: false,
        }];
        let path = tmp_file(&serde_json::to_string(&ctx).unwrap());
        let loaded = load_agent_context_from_file(&path).unwrap();
        assert_eq!(loaded.call_graph.len(), 1);
        assert_eq!(
            loaded.call_graph[0].input_selector,
            Some([0xde, 0xad, 0xbe, 0xef])
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_from_dir_returns_all_sorted() {
        let dir = tmp_dir();
        for (name, block) in [("c.json", 3u64), ("a.json", 1), ("b.json", 2)] {
            let mut ctx = minimal_context();
            ctx.block_number = block;
            fs::write(dir.join(name), serde_json::to_string(&ctx).unwrap()).unwrap();
        }
        let contexts = load_agent_contexts_from_dir(&dir).unwrap();
        assert_eq!(contexts.len(), 3);
        assert_eq!(contexts[0].block_number, 1); // a.json
        assert_eq!(contexts[1].block_number, 2); // b.json
        assert_eq!(contexts[2].block_number, 3); // c.json
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_from_dir_skips_non_json() {
        let dir = tmp_dir();
        let ctx = minimal_context();
        fs::write(dir.join("valid.json"), serde_json::to_string(&ctx).unwrap()).unwrap();
        fs::write(dir.join("readme.txt"), "ignored").unwrap();
        let contexts = load_agent_contexts_from_dir(&dir).unwrap();
        assert_eq!(contexts.len(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_from_dir_empty_returns_empty_vec() {
        let dir = tmp_dir();
        let contexts = load_agent_contexts_from_dir(&dir).unwrap();
        assert!(contexts.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn load_from_dir_missing_returns_error() {
        let result = load_agent_contexts_from_dir(Path::new("/nonexistent/dir"));
        assert!(result.is_err());
    }

    // ── Integration tests: actual fixture files ─────────────────────────────

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ai")
    }

    #[test]
    fn load_actual_attack_fixtures() {
        let dir = fixtures_dir();
        for name in [
            "attack_reentrancy_dao.json",
            "attack_flash_loan_euler.json",
            "attack_price_manipulation_balancer.json",
        ] {
            let ctx = load_agent_context_from_file(&dir.join(name))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(ctx.block_number > 0, "{name}: block_number should be > 0");
            assert!(ctx.gas_used > 0, "{name}: gas_used should be > 0");
        }
    }

    #[test]
    fn load_actual_normal_fixtures() {
        let dir = fixtures_dir();
        let normal_files = [
            "normal_eth_transfer_simple.json",
            "normal_eth_transfer_large.json",
            "normal_eth_transfer_contract.json",
            "normal_defi_swap_uniswap.json",
            "normal_defi_swap_multi_hop.json",
            "normal_defi_liquidity_add.json",
            "normal_multi_call_batch.json",
            "normal_multi_call_governance.json",
            "normal_contract_deploy_simple.json",
            "normal_contract_deploy_factory.json",
        ];
        for name in normal_files {
            let ctx = load_agent_context_from_file(&dir.join(name))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(ctx.block_number > 0, "{name}: block_number should be > 0");
        }
    }

    #[test]
    fn load_all_fixtures_from_dir() {
        let dir = fixtures_dir();
        let contexts = load_agent_contexts_from_dir(&dir).unwrap();
        assert_eq!(
            contexts.len(),
            13,
            "expected 13 fixture files (3 attack + 10 normal)"
        );
    }
}
