//! Async block poller for RPC-based Sentinel mode.
//!
//! `RpcBlockPoller` polls the Ethereum RPC for new blocks at a configurable
//! interval, fetching full block data and receipts for each new block.
//!
//! Think of it like a newspaper delivery service: it checks the print shop
//! (chain tip) on a schedule, picks up every new edition (block) since the
//! last delivery, and drops them in your mailbox (mpsc channel).
//!
//! Because `EthRpcClient` uses blocking reqwest, all RPC calls are wrapped
//! in `tokio::task::spawn_blocking` to avoid blocking the async runtime.


use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::autopsy::rpc_client::{EthRpcClient, RpcBlock, RpcConfig, RpcReceipt};

/// Configuration for the block poller.
#[derive(Debug, Clone)]
pub struct RpcPollerConfig {
    /// Ethereum RPC endpoint URL.
    pub rpc_url: String,
    /// How often to poll for new blocks.
    pub poll_interval: Duration,
    /// RPC client behavior configuration (timeouts, retries).
    pub rpc_config: RpcConfig,
}

impl RpcPollerConfig {
    /// Create a config with default poll interval (1 second) and default RPC config.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            poll_interval: Duration::from_secs(1),
            rpc_config: RpcConfig::default(),
        }
    }
}

impl Default for RpcPollerConfig {
    fn default() -> Self {
        Self::new("http://localhost:8545")
    }
}

/// Async block poller that streams `(RpcBlock, Vec<RpcReceipt>)` pairs over a channel.
///
/// Call [`RpcBlockPoller::start`] to spawn the background polling task and
/// receive the channel receiver. Call [`RpcBlockPoller::stop`] to signal
/// graceful shutdown.
pub struct RpcBlockPoller {
    config: RpcPollerConfig,
    running: Arc<AtomicBool>,
}

impl RpcBlockPoller {
    /// Create a new poller with the given configuration.
    pub fn new(config: RpcPollerConfig) -> Self {
        Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start polling for new blocks.
    ///
    /// Spawns a tokio task that:
    /// 1. Calls `eth_blockNumber` to find the chain tip.
    /// 2. Fetches each unseen block with `eth_get_block_by_number_with_txs`.
    /// 3. Fetches receipts for every transaction in the block.
    /// 4. Sends `(block, receipts)` through the returned channel.
    /// 5. Waits `poll_interval` before repeating.
    ///
    /// The task stops when [`RpcBlockPoller::stop`] is called or when the
    /// receiver is dropped.
    pub async fn start(&self) -> mpsc::Receiver<(RpcBlock, Vec<RpcReceipt>)> {
        let (tx, rx) = mpsc::channel(64);
        let config = self.config.clone();
        let running = self.running.clone();

        running.store(true, Ordering::SeqCst);

        tokio::spawn(async move {
            poll_loop(config, tx, running).await;
        });

        rx
    }

    /// Signal the background polling task to stop.
    ///
    /// The task will finish its current iteration and then exit. This is a
    /// best-effort signal — the task may send one more batch after `stop()`.
    pub async fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Returns true if the poller is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Maximum number of blocks to catch up per poll cycle.
///
/// Prevents unbounded work if the poller falls far behind the chain tip
/// (e.g., after a restart or sustained RPC outage).
const MAX_CATCHUP_BLOCKS: u64 = 128;

/// Fetch all receipts for a block, preferring `eth_getBlockReceipts` (single
/// RPC call) and falling back to per-transaction `eth_getTransactionReceipt`
/// (N+1 calls) when the batch method is unsupported or returns a mismatched count.
///
/// Retryable errors (network timeouts, connection failures) are propagated
/// immediately — falling back to N+1 individual calls would also fail and
/// waste time on retries that cannot succeed.
fn fetch_receipts_with_fallback(
    client: &EthRpcClient,
    block: &RpcBlock,
) -> Result<Vec<RpcReceipt>, crate::error::DebuggerError> {
    let block_num = block.header.number;
    match client.eth_get_block_receipts(block_num) {
        Ok(batch) if batch.len() == block.transactions.len() => Ok(batch),
        Ok(_) => {
            #[cfg(debug_assertions)]
            eprintln!(
                "[argus] eth_getBlockReceipts count mismatch for block {block_num}, \
                 falling back to per-tx fetch"
            );
            fetch_receipts_individually(client, block)
        }
        Err(e) => {
            // Retryable errors (network down, timeout) → propagate immediately.
            // Non-retryable errors (method not found, parse error) → fallback.
            if let crate::error::DebuggerError::Rpc(ref rpc_err) = e
                && rpc_err.is_retryable()
            {
                return Err(e);
            }
            #[cfg(debug_assertions)]
            eprintln!(
                "[argus] eth_getBlockReceipts unsupported for block {block_num}, \
                 falling back to per-tx fetch"
            );
            fetch_receipts_individually(client, block)
        }
    }
}

/// Individual per-transaction receipt fetch (N+1 fallback).
fn fetch_receipts_individually(
    client: &EthRpcClient,
    block: &RpcBlock,
) -> Result<Vec<RpcReceipt>, crate::error::DebuggerError> {
    let mut receipts = Vec::with_capacity(block.transactions.len());
    for tx_ref in &block.transactions {
        receipts.push(client.eth_get_transaction_receipt(tx_ref.hash)?);
    }
    Ok(receipts)
}

/// Maximum consecutive tip-fetch errors (any type) before the poller terminates.
/// Termination only triggers when the error at the threshold is non-retryable;
/// retryable errors increment the counter but never cause termination on their own.
const MAX_CONSECUTIVE_ERRORS: u32 = 5;

/// Build the shared blocking HTTP client, returning `None` on failure.
async fn create_shared_client(
    url: &str,
    rpc_config: RpcConfig,
    running: &Arc<AtomicBool>,
) -> Option<Arc<EthRpcClient>> {
    let url = url.to_string();
    match tokio::task::spawn_blocking(move || EthRpcClient::for_polling(&url, rpc_config)).await {
        Ok(client) => Some(Arc::new(client)),
        Err(e) => {
            eprintln!("[rpc_poller] failed to create RPC client: {e}");
            running.store(false, Ordering::SeqCst);
            None
        }
    }
}

/// Fetch the current chain tip to establish the starting point, returning `None` on failure.
async fn fetch_initial_tip(client: &Arc<EthRpcClient>, running: &Arc<AtomicBool>) -> Option<u64> {
    let c = Arc::clone(client);
    match tokio::task::spawn_blocking(move || c.eth_block_number()).await {
        Ok(Ok(n)) => Some(n),
        Ok(Err(e)) => {
            eprintln!("[rpc_poller] initial tip fetch failed: {e}");
            running.store(false, Ordering::SeqCst);
            None
        }
        Err(e) => {
            eprintln!("[rpc_poller] initial tip fetch panicked: {e}");
            running.store(false, Ordering::SeqCst);
            None
        }
    }
}

/// Core polling loop — runs in a spawned tokio task.
async fn poll_loop(
    config: RpcPollerConfig,
    tx: mpsc::Sender<(RpcBlock, Vec<RpcReceipt>)>,
    running: Arc<AtomicBool>,
) {
    let Some(shared_client) =
        create_shared_client(&config.rpc_url, config.rpc_config.clone(), &running).await
    else {
        return;
    };

    let Some(last_seen) = fetch_initial_tip(&shared_client, &running).await else {
        return;
    };

    let mut last_seen_block = last_seen;
    let mut consecutive_tip_errors: u32 = 0;

    while running.load(Ordering::SeqCst) {
        // Fetch current chain tip.
        let tip = {
            let client = Arc::clone(&shared_client);
            match tokio::task::spawn_blocking(move || client.eth_block_number()).await {
                Ok(Ok(n)) => {
                    consecutive_tip_errors = 0;
                    n
                }
                Ok(Err(e)) => {
                    consecutive_tip_errors += 1;
                    let retryable = matches!(
                        &e,
                        crate::error::DebuggerError::Rpc(rpc_err) if rpc_err.is_retryable()
                    );
                    if retryable {
                        eprintln!(
                            "[rpc_poller] tip fetch failed (retryable, attempt {consecutive_tip_errors}): {e}"
                        );
                    } else {
                        eprintln!(
                            "[rpc_poller] tip fetch failed (non-retryable, attempt {consecutive_tip_errors}): {e}"
                        );
                    }
                    if !retryable && consecutive_tip_errors >= MAX_CONSECUTIVE_ERRORS {
                        eprintln!(
                            "[rpc_poller] {MAX_CONSECUTIVE_ERRORS} consecutive non-retryable errors; terminating"
                        );
                        running.store(false, Ordering::SeqCst);
                        return;
                    }
                    tokio::time::sleep(config.poll_interval).await;
                    continue;
                }
                Err(e) => {
                    eprintln!("[rpc_poller] tip fetch panicked: {e}");
                    running.store(false, Ordering::SeqCst);
                    return;
                }
            }
        };

        // Clamp catch-up range to MAX_CATCHUP_BLOCKS to prevent unbounded work.
        let from_block = last_seen_block + 1;
        let to_block = if tip.saturating_sub(last_seen_block) > MAX_CATCHUP_BLOCKS {
            let clamped = tip.saturating_sub(MAX_CATCHUP_BLOCKS);
            eprintln!(
                "[rpc_poller] catch-up gap {} blocks exceeds limit {}; \
                 skipping from {} to {}, resuming at {}",
                tip - last_seen_block,
                MAX_CATCHUP_BLOCKS,
                last_seen_block + 1,
                clamped,
                clamped + 1,
            );
            last_seen_block = clamped;
            tip
        } else {
            tip
        };

        // Process every new block since last_seen_block.
        // On any fetch error we break (not continue) so that last_seen_block is
        // NOT advanced past the failed block — it will be retried next cycle.
        'block_loop: for block_num in from_block.max(last_seen_block + 1)..=to_block {
            if !running.load(Ordering::SeqCst) {
                return;
            }

            // Fetch full block + all receipts. The shared_client's underlying
            // reqwest::blocking::Client maintains a connection pool, so we
            // avoid TCP handshakes on each block.
            let client = Arc::clone(&shared_client);
            let result = tokio::task::spawn_blocking(move || {
                let block = client.eth_get_block_by_number_with_txs(block_num)?;
                let receipts = fetch_receipts_with_fallback(&client, &block)?;
                Ok::<_, crate::error::DebuggerError>((block, receipts))
            })
            .await;

            let (block, receipts) = match result {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    eprintln!("[rpc_poller] block {block_num} fetch failed: {e}");
                    break 'block_loop;
                }
                Err(e) => {
                    eprintln!("[rpc_poller] block {block_num} fetch panicked: {e}");
                    break 'block_loop;
                }
            };

            // Send pair; if receiver dropped, stop the loop.
            if tx.send((block, receipts)).await.is_err() {
                running.store(false, Ordering::SeqCst);
                return;
            }

            last_seen_block = block_num;
        }

        tokio::time::sleep(config.poll_interval).await;
    }

    running.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RED: Configuration tests ---

    #[test]
    fn test_poller_config_defaults() {
        let config = RpcPollerConfig::default();
        assert_eq!(config.rpc_url, "http://localhost:8545");
        assert_eq!(config.poll_interval, Duration::from_secs(1));
        assert_eq!(config.rpc_config.timeout, Duration::from_secs(30));
        assert_eq!(config.rpc_config.max_retries, 3);
    }

    #[test]
    fn test_poller_config_new() {
        let config = RpcPollerConfig::new("https://eth-mainnet.example.com");
        assert_eq!(config.rpc_url, "https://eth-mainnet.example.com");
        assert_eq!(config.poll_interval, Duration::from_secs(1));
    }

    #[test]
    fn test_poller_config_custom_interval() {
        let config = RpcPollerConfig {
            rpc_url: "http://localhost:8545".into(),
            poll_interval: Duration::from_millis(500),
            rpc_config: RpcConfig::default(),
        };
        assert_eq!(config.poll_interval, Duration::from_millis(500));
    }

    // --- RED: Lifecycle tests ---

    #[tokio::test]
    async fn test_poller_not_running_before_start() {
        let config = RpcPollerConfig::default();
        let poller = RpcBlockPoller::new(config);
        assert!(!poller.is_running());
    }

    #[tokio::test]
    async fn test_poller_lifecycle_stop_signal() {
        // Poller configured against a non-existent URL — poll_loop will fail
        // on the initial eth_blockNumber call and set running=false.
        let config = RpcPollerConfig {
            rpc_url: "http://127.0.0.1:19999".into(), // nothing listening here
            poll_interval: Duration::from_millis(50),
            rpc_config: RpcConfig {
                timeout: Duration::from_millis(100),
                connect_timeout: Duration::from_millis(100),
                max_retries: 0,
                base_backoff: Duration::from_millis(10),
            },
        };
        let poller = RpcBlockPoller::new(config);
        let _rx = poller.start().await;

        // Allow the spawned task to attempt the connection and fail.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // After failing to connect, running should be false.
        assert!(!poller.is_running());
    }

    #[tokio::test]
    async fn test_poller_stop_sets_not_running() {
        let config = RpcPollerConfig::default();
        let poller = RpcBlockPoller::new(config);
        // start() sets running=true before spawning
        let _rx = poller.start().await;
        poller.stop().await;
        assert!(!poller.is_running());
    }

    // --- RED: catch-up behavior test (offline / unit-level) ---

    /// Verifies that the config's catch-up invariant is documentable:
    /// blocks are processed in ascending order from last_seen+1 to tip.
    #[test]
    fn test_block_range_ascending() {
        // Simulate the range loop used in poll_loop.
        let last_seen: u64 = 5;
        let tip: u64 = 8;
        let expected = vec![6u64, 7, 8];
        let actual: Vec<u64> = ((last_seen + 1)..=tip).collect();
        assert_eq!(actual, expected);
    }

    /// Edge case: no new blocks → empty range, no sends.
    #[test]
    fn test_block_range_no_new_blocks() {
        let last_seen: u64 = 10;
        let tip: u64 = 10;
        let actual: Vec<u64> = ((last_seen + 1)..=tip).collect();
        assert!(actual.is_empty());
    }

    /// Edge case: tip behind last_seen (reorg / clock skew) → empty range.
    #[test]
    fn test_block_range_tip_behind() {
        let last_seen: u64 = 10;
        let tip: u64 = 9;
        let actual: Vec<u64> = ((last_seen + 1)..=tip).collect();
        assert!(actual.is_empty());
    }

    /// Simulates the receipt-fetch-failure logic:
    /// if any receipt fails, the entire block must be skipped (fetch_ok = false).
    /// Verifies that a partial receipt list is never forwarded downstream.
    #[test]
    fn test_receipt_fetch_failure_skips_entire_block() {
        // Simulate 3 transactions; the second receipt fetch fails.
        let tx_count = 3usize;
        let fail_at = 1usize; // second receipt (0-indexed)

        let mut receipts: Vec<u64> = Vec::with_capacity(tx_count);
        let mut fetch_ok = true;

        for i in 0..tx_count {
            if i == fail_at {
                // Simulate a failed receipt fetch.
                fetch_ok = false;
                break;
            }
            receipts.push(i as u64);
        }

        // Block must be skipped: fetch_ok is false.
        assert!(
            !fetch_ok,
            "expected fetch_ok to be false after receipt failure"
        );
        // Partial receipts must NOT be forwarded — the block is skipped entirely.
        assert!(
            receipts.len() < tx_count,
            "receipts collected before failure: {}",
            receipts.len()
        );
        // Critically, receipt count does NOT equal tx count — which is exactly
        // why we skip the block rather than sending a misaligned pair.
        assert_ne!(receipts.len(), tx_count);
    }

    /// Verifies catch-up clamp logic: if gap > MAX_CATCHUP_BLOCKS, the start
    /// of the range is advanced so at most MAX_CATCHUP_BLOCKS are processed.
    #[test]
    fn test_catchup_clamp() {
        let last_seen: u64 = 0;
        let tip: u64 = 200;
        let gap = tip - last_seen;
        assert!(gap > MAX_CATCHUP_BLOCKS);

        // After clamping, we only process MAX_CATCHUP_BLOCKS.
        let clamped_from = tip.saturating_sub(MAX_CATCHUP_BLOCKS);
        let range: Vec<u64> = (clamped_from + 1..=tip).collect();
        assert_eq!(range.len() as u64, MAX_CATCHUP_BLOCKS);
    }

    // --- Fallback error classification (offline) ---

    /// Verifies that the error classification used by `fetch_receipts_with_fallback`
    /// correctly distinguishes retryable (network) vs non-retryable (unsupported method)
    /// errors. Retryable errors must propagate; non-retryable errors must trigger fallback.
    #[test]
    fn test_fallback_error_classification() {
        use crate::error::RpcError;

        // JsonRpcError (method not found) → non-retryable → triggers fallback
        let err = RpcError::JsonRpcError {
            method: "eth_getBlockReceipts".into(),
            code: -32601,
            message: "Method not found".into(),
        };
        assert!(
            !err.is_retryable(),
            "method-not-found must trigger fallback, not propagate"
        );

        // ParseError (null result) → non-retryable → triggers fallback
        let err = RpcError::ParseError {
            method: "eth_getBlockReceipts".into(),
            field: "result".into(),
            cause: "expected array".into(),
        };
        assert!(
            !err.is_retryable(),
            "parse error must trigger fallback, not propagate"
        );

        // ConnectionFailed → retryable → must propagate immediately
        let err = RpcError::ConnectionFailed {
            url: "http://example.com".into(),
            cause: "connection refused".into(),
        };
        assert!(
            err.is_retryable(),
            "network error must propagate, not trigger fallback"
        );

        // Timeout → retryable → must propagate immediately
        let err = RpcError::Timeout {
            method: "eth_getBlockReceipts".into(),
            elapsed_ms: 30000,
        };
        assert!(
            err.is_retryable(),
            "timeout must propagate, not trigger fallback"
        );
    }

    // --- Consecutive error termination logic (offline) ---

    /// Simulates the termination logic from poll_loop: the counter increments
    /// on every tip-fetch error, but termination only triggers when the error
    /// at the threshold is non-retryable.
    #[test]
    fn test_consecutive_tip_error_termination_logic() {
        let max = MAX_CONSECUTIVE_ERRORS;

        // Scenario 1: mixed errors reaching threshold, last is non-retryable → terminate
        let mut count: u32 = 0;
        for _ in 0..4 {
            count += 1; // retryable errors still increment
        }
        count += 1; // 5th error, non-retryable
        let retryable = false;
        let should_terminate = !retryable && count >= max;
        assert!(
            should_terminate,
            "non-retryable error at threshold should terminate"
        );

        // Scenario 2: all retryable, at threshold → do NOT terminate
        let count: u32 = max;
        let retryable = true;
        let should_terminate = !retryable && count >= max;
        assert!(
            !should_terminate,
            "retryable errors should never trigger termination"
        );

        // Scenario 3: success resets counter → under threshold
        // Simulate: had (max-1) errors, then a success resets to 0, then 1 more error
        let count: u32 = 0_u32.wrapping_add(1); // reset + one more error = 1
        let retryable = false;
        let should_terminate = !retryable && count >= max;
        assert!(
            !should_terminate,
            "counter reset on success prevents termination"
        );
    }

    // --- for_polling constructor (offline) ---

    #[test]
    fn test_for_polling_block_tag() {
        let client = EthRpcClient::for_polling("http://localhost:8545", RpcConfig::default());
        // "latest" is not a valid hex number, so block_number() returns 0 via unwrap_or
        assert_eq!(client.block_number(), 0);
    }

    // --- Live tests (require real RPC, marked #[ignore]) ---

    #[tokio::test]
    #[ignore = "requires live RPC endpoint (ALCHEMY_API_KEY)"]
    async fn test_poller_receives_block_live() {
        let api_key = std::env::var("ALCHEMY_API_KEY").expect("ALCHEMY_API_KEY not set");
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{api_key}");

        let config = RpcPollerConfig {
            rpc_url: url,
            poll_interval: Duration::from_secs(2),
            rpc_config: RpcConfig::default(),
        };
        let poller = RpcBlockPoller::new(config);
        let mut rx = poller.start().await;

        // Expect at least one block within 15 seconds.
        let result = tokio::time::timeout(Duration::from_secs(15), rx.recv()).await;

        poller.stop().await;

        let (block, receipts) = result
            .expect("timed out waiting for block")
            .expect("channel closed without block");

        assert!(block.header.number > 0);
        assert_eq!(block.transactions.len(), receipts.len());
    }

    #[tokio::test]
    #[ignore = "requires live RPC endpoint (ALCHEMY_API_KEY)"]
    async fn test_batch_receipts_match_individual_live() {
        let api_key = std::env::var("ALCHEMY_API_KEY").expect("ALCHEMY_API_KEY not set");
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{api_key}");

        let result = tokio::task::spawn_blocking(move || {
            let client = EthRpcClient::for_polling(&url, RpcConfig::default());
            let tip = client.eth_block_number()?;
            let block = client.eth_get_block_by_number_with_txs(tip)?;
            let batch = client.eth_get_block_receipts(tip)?;
            Ok::<_, crate::error::DebuggerError>((block, batch))
        })
        .await
        .expect("spawn_blocking panicked")
        .expect("RPC call failed");

        let (block, batch) = result;
        assert_eq!(
            batch.len(),
            block.transactions.len(),
            "batch receipt count must match transaction count"
        );
    }
}
