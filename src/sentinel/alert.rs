//! Alert dispatching, deduplication, and rate limiting for the Sentinel system.
//!
//! This module provides composable wrappers around [`AlertHandler`] that form
//! a processing pipeline:
//!
//! ```text
//!   SentinelAlert
//!     -> AlertRateLimiter    (drop if over budget)
//!     -> AlertDeduplicator   (drop if seen recently)
//!     -> AlertDispatcher     (fan-out to multiple outputs)
//!        -> JsonlFileAlertHandler
//!        -> StdoutAlertHandler
//!        -> (WebhookAlertHandler, etc.)
//! ```
//!
//! Each wrapper implements `AlertHandler` itself, so they can be nested freely.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use super::service::AlertHandler;
use super::types::SentinelAlert;

// ---------------------------------------------------------------------------
// AlertDispatcher (composite / fan-out)
// ---------------------------------------------------------------------------

/// Dispatches a single alert to multiple downstream handlers in registration order.
///
/// Implements the composite pattern: `AlertDispatcher` itself is an `AlertHandler`,
/// so it can be nested inside deduplicators or rate limiters.
#[derive(Default)]
pub struct AlertDispatcher {
    handlers: Vec<Box<dyn AlertHandler>>,
}

impl AlertDispatcher {
    /// Create a dispatcher with pre-built handlers.
    pub fn new(handlers: Vec<Box<dyn AlertHandler>>) -> Self {
        Self { handlers }
    }

    /// Add a handler to the end of the dispatch chain.
    pub fn add_handler(&mut self, handler: Box<dyn AlertHandler>) {
        self.handlers.push(handler);
    }
}

impl AlertHandler for AlertDispatcher {
    fn on_alert(&self, alert: SentinelAlert) {
        for handler in &self.handlers {
            handler.on_alert(alert.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// JsonlFileAlertHandler
// ---------------------------------------------------------------------------

/// Appends each alert as a single JSON line to a file (JSON Lines format).
///
/// The file is opened with `append(true).create(true)` on every write, so
/// external log-rotation tools can safely rename the file between writes.
pub struct JsonlFileAlertHandler {
    path: PathBuf,
}

impl JsonlFileAlertHandler {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl AlertHandler for JsonlFileAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        let json = match serde_json::to_string(&alert) {
            Ok(j) => j,
            Err(e) => {
                eprintln!(
                    "[SENTINEL] Failed to serialize alert for JSONL output: {}",
                    e
                );
                return;
            }
        };

        let result = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut file| writeln!(file, "{}", json));

        if let Err(e) = result {
            eprintln!(
                "[SENTINEL] Failed to write alert to {}: {}",
                self.path.display(),
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// StdoutAlertHandler
// ---------------------------------------------------------------------------

/// Prints each alert as a single JSON line to stdout.
///
/// Useful for containerized deployments where stdout is captured by the
/// orchestrator (Docker, Kubernetes, systemd journal).
pub struct StdoutAlertHandler;

impl AlertHandler for StdoutAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        match serde_json::to_string(&alert) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("[SENTINEL] Failed to serialize alert for stdout: {}", e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AlertDeduplicator
// ---------------------------------------------------------------------------

/// Deduplication key used to identify "same" alerts within a sliding block window.
///
/// With the `autopsy` feature enabled, deduplication is pattern-aware: the same
/// attack pattern against the same contract is suppressed even across different
/// transactions. Without `autopsy`, deduplication is purely TX-hash based.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DeduplicationKey {
    /// Pattern name + target contract (autopsy) or stringified tx_hash (non-autopsy).
    identity: String,
}

/// Suppresses duplicate alerts within a configurable block window.
///
/// Wraps an inner `AlertHandler` and only forwards alerts whose deduplication
/// key has not been seen within the last `window_blocks` blocks.
pub struct AlertDeduplicator {
    inner: Box<dyn AlertHandler>,
    window_blocks: u64,
    /// Maps dedup key -> last seen block number.
    seen: Mutex<HashMap<DeduplicationKey, u64>>,
}

impl AlertDeduplicator {
    /// Create a deduplicator with a custom block window.
    pub fn new(inner: Box<dyn AlertHandler>, window_blocks: u64) -> Self {
        Self {
            inner,
            window_blocks,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Create a deduplicator with the default 10-block window.
    pub fn with_default_window(inner: Box<dyn AlertHandler>) -> Self {
        Self::new(inner, 10)
    }

    /// Extract deduplication keys from an alert.
    ///
    /// With `autopsy`: one key per detected pattern (pattern_name + target_contract).
    /// Without `autopsy`: single key from tx_hash.
    fn extract_keys(alert: &SentinelAlert) -> Vec<DeduplicationKey> {
        #[cfg(feature = "autopsy")]
        {
            if !alert.detected_patterns.is_empty() {
                return alert
                    .detected_patterns
                    .iter()
                    .map(|dp| {
                        let pattern_name = match &dp.pattern {
                            crate::autopsy::types::AttackPattern::Reentrancy {
                                target_contract,
                                ..
                            } => format!("Reentrancy:{:#x}", target_contract),
                            crate::autopsy::types::AttackPattern::FlashLoan {
                                provider, ..
                            } => {
                                let addr = provider.unwrap_or_default();
                                format!("FlashLoan:{:#x}", addr)
                            }
                            crate::autopsy::types::AttackPattern::PriceManipulation { .. } => {
                                "PriceManipulation:global".to_string()
                            }
                            crate::autopsy::types::AttackPattern::AccessControlBypass {
                                contract,
                                ..
                            } => format!("AccessControlBypass:{:#x}", contract),
                        };
                        DeduplicationKey {
                            identity: pattern_name,
                        }
                    })
                    .collect();
            }
        }

        // Fallback (no autopsy feature or no detected patterns): use tx_hash
        vec![DeduplicationKey {
            identity: format!("{:#x}", alert.tx_hash),
        }]
    }
}

impl AlertHandler for AlertDeduplicator {
    fn on_alert(&self, alert: SentinelAlert) {
        let keys = Self::extract_keys(&alert);
        let block = alert.block_number;

        let mut seen = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Evict stale entries outside the window
        seen.retain(|_, last_block| block.saturating_sub(*last_block) < self.window_blocks);

        // Check if ALL keys are duplicates (suppress only if every key was seen)
        let any_new = keys.iter().any(|k| {
            seen.get(k)
                .is_none_or(|last| block.saturating_sub(*last) >= self.window_blocks)
        });

        if !any_new {
            eprintln!(
                "[SENTINEL] Suppressed duplicate alert for tx={:#x} block={}",
                alert.tx_hash, alert.block_number
            );
            return;
        }

        // Record all keys
        for key in keys {
            seen.insert(key, block);
        }

        drop(seen);
        self.inner.on_alert(alert);
    }
}

// ---------------------------------------------------------------------------
// AlertRateLimiter
// ---------------------------------------------------------------------------

/// Limits the number of alerts forwarded per minute.
///
/// Uses a sliding window of timestamps. Alerts exceeding the budget are
/// silently dropped with an `eprintln!` warning.
pub struct AlertRateLimiter {
    inner: Box<dyn AlertHandler>,
    max_per_minute: usize,
    timestamps: Mutex<VecDeque<Instant>>,
}

impl AlertRateLimiter {
    /// Create a rate limiter with a custom budget.
    pub fn new(inner: Box<dyn AlertHandler>, max_per_minute: usize) -> Self {
        Self {
            inner,
            max_per_minute,
            timestamps: Mutex::new(VecDeque::new()),
        }
    }

    /// Create a rate limiter with the default budget of 30 alerts/minute.
    pub fn with_default_limit(inner: Box<dyn AlertHandler>) -> Self {
        Self::new(inner, 30)
    }
}

impl AlertHandler for AlertRateLimiter {
    fn on_alert(&self, alert: SentinelAlert) {
        let now = Instant::now();
        let one_minute = std::time::Duration::from_secs(60);

        let mut timestamps = match self.timestamps.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Evict entries older than 60 seconds
        while timestamps
            .front()
            .is_some_and(|t| now.duration_since(*t) >= one_minute)
        {
            timestamps.pop_front();
        }

        if timestamps.len() >= self.max_per_minute {
            eprintln!(
                "[SENTINEL] Rate limit exceeded ({}/min), suppressing alert for tx={:#x}",
                self.max_per_minute, alert.tx_hash
            );
            return;
        }

        timestamps.push_back(now);
        drop(timestamps);
        self.inner.on_alert(alert);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{H256, U256};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    /// Test handler that counts how many alerts it received.
    struct CountingHandler {
        count: Arc<AtomicUsize>,
    }

    impl CountingHandler {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    count: count.clone(),
                },
                count,
            )
        }
    }

    impl AlertHandler for CountingHandler {
        fn on_alert(&self, _alert: SentinelAlert) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn make_alert(block_number: u64, tx_hash_byte: u8) -> SentinelAlert {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = tx_hash_byte;
        SentinelAlert {
            block_number,
            block_hash: H256::zero(),
            tx_hash: H256::from(hash_bytes),
            tx_index: 0,
            alert_priority: super::super::types::AlertPriority::High,
            suspicion_reasons: vec![],
            suspicion_score: 0.7,
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: "test alert".to_string(),
            total_steps: 100,
            feature_vector: None,
        }
    }

    // -- AlertDispatcher tests --

    #[test]
    fn dispatcher_fans_out_to_all_handlers() {
        let (h1, c1) = CountingHandler::new();
        let (h2, c2) = CountingHandler::new();
        let dispatcher = AlertDispatcher::new(vec![Box::new(h1), Box::new(h2)]);

        dispatcher.on_alert(make_alert(1, 0xAA));

        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatcher_default_is_empty() {
        let dispatcher = AlertDispatcher::default();
        // Should not panic even with no handlers
        dispatcher.on_alert(make_alert(1, 0xBB));
    }

    #[test]
    fn dispatcher_add_handler() {
        let mut dispatcher = AlertDispatcher::default();
        let (h, count) = CountingHandler::new();
        dispatcher.add_handler(Box::new(h));

        dispatcher.on_alert(make_alert(1, 0xCC));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    // -- StdoutAlertHandler tests --

    #[test]
    fn stdout_handler_does_not_panic() {
        let handler = StdoutAlertHandler;
        handler.on_alert(make_alert(1, 0xDD));
    }

    // -- JsonlFileAlertHandler tests --

    #[test]
    fn jsonl_handler_writes_to_file() {
        let dir = std::env::temp_dir().join("sentinel_test_jsonl");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("alerts.jsonl");
        let _ = std::fs::remove_file(&path);

        let handler = JsonlFileAlertHandler::new(path.clone());
        handler.on_alert(make_alert(42, 0x01));
        handler.on_alert(make_alert(43, 0x02));

        let content = std::fs::read_to_string(&path).expect("file should exist");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
            assert!(parsed.get("block_number").is_some());
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn jsonl_handler_bad_path_does_not_panic() {
        let handler = JsonlFileAlertHandler::new(PathBuf::from("/nonexistent/dir/file.jsonl"));
        // Should print eprintln warning but not panic
        handler.on_alert(make_alert(1, 0xEE));
    }

    // -- AlertDeduplicator tests --

    #[test]
    fn deduplicator_suppresses_same_tx_within_window() {
        let (h, count) = CountingHandler::new();
        let dedup = AlertDeduplicator::new(Box::new(h), 5);

        // Same tx_hash, same block
        dedup.on_alert(make_alert(10, 0xAA));
        dedup.on_alert(make_alert(10, 0xAA));
        dedup.on_alert(make_alert(11, 0xAA));

        // First should pass, second and third suppressed (within 5-block window)
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn deduplicator_allows_after_window_expires() {
        let (h, count) = CountingHandler::new();
        let dedup = AlertDeduplicator::new(Box::new(h), 5);

        dedup.on_alert(make_alert(10, 0xAA));
        // Block 16 is 6 blocks later (>= window of 5)
        dedup.on_alert(make_alert(16, 0xAA));

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn deduplicator_allows_different_tx_hashes() {
        let (h, count) = CountingHandler::new();
        let dedup = AlertDeduplicator::new(Box::new(h), 5);

        dedup.on_alert(make_alert(10, 0xAA));
        dedup.on_alert(make_alert(10, 0xBB));

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn deduplicator_default_window() {
        let (h, count) = CountingHandler::new();
        let dedup = AlertDeduplicator::with_default_window(Box::new(h));

        dedup.on_alert(make_alert(1, 0xAA));
        dedup.on_alert(make_alert(5, 0xAA)); // within 10-block window
        dedup.on_alert(make_alert(12, 0xAA)); // block 12, 11 blocks after block 1 -> allowed

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    // -- AlertRateLimiter tests --

    #[test]
    fn rate_limiter_allows_under_budget() {
        let (h, count) = CountingHandler::new();
        let limiter = AlertRateLimiter::new(Box::new(h), 5);

        for i in 0..5 {
            limiter.on_alert(make_alert(1, i));
        }

        assert_eq!(count.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn rate_limiter_suppresses_over_budget() {
        let (h, count) = CountingHandler::new();
        let limiter = AlertRateLimiter::new(Box::new(h), 3);

        for i in 0..10 {
            limiter.on_alert(make_alert(1, i));
        }

        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn rate_limiter_default_budget() {
        let (h, count) = CountingHandler::new();
        let limiter = AlertRateLimiter::with_default_limit(Box::new(h));

        for i in 0..35 {
            limiter.on_alert(make_alert(1, i as u8));
        }

        // Default is 30/min
        assert_eq!(count.load(Ordering::SeqCst), 30);
    }

    // -- Composition tests --

    #[test]
    fn pipeline_rate_limit_then_dedup_then_dispatch() {
        let (h1, c1) = CountingHandler::new();
        let (h2, c2) = CountingHandler::new();
        let dispatcher = AlertDispatcher::new(vec![Box::new(h1), Box::new(h2)]);
        let dedup = AlertDeduplicator::new(Box::new(dispatcher), 5);
        let limiter = AlertRateLimiter::new(Box::new(dedup), 10);

        // Send 3 unique + 2 duplicate alerts
        limiter.on_alert(make_alert(1, 0x01));
        limiter.on_alert(make_alert(1, 0x02));
        limiter.on_alert(make_alert(1, 0x03));
        limiter.on_alert(make_alert(1, 0x01)); // dup
        limiter.on_alert(make_alert(1, 0x02)); // dup

        // Rate limiter passes all 5 (under budget of 10)
        // Dedup suppresses 2 duplicates -> 3 unique forwarded
        // Dispatcher fans out to both handlers
        assert_eq!(c1.load(Ordering::SeqCst), 3);
        assert_eq!(c2.load(Ordering::SeqCst), 3);
    }
}
