//! SentinelService, BlockObserver, and reentrancy E2E tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ethrex_blockchain::BlockObserver;
use ethrex_common::types::{
    Block, BlockBody, BlockHeader, LegacyTransaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};
use ethrex_storage::{EngineType, Store};

use crate::sentinel::service::{AlertHandler, LogAlertHandler, SentinelService};
use crate::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelConfig};

/// Test alert handler that counts alerts.
struct CountingAlertHandler {
    count: Arc<AtomicUsize>,
}

impl AlertHandler for CountingAlertHandler {
    fn on_alert(&self, _alert: SentinelAlert) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

fn make_empty_block(number: u64) -> Block {
    Block {
        header: BlockHeader {
            number,
            ..Default::default()
        },
        body: BlockBody::default(),
    }
}

fn make_receipt(succeeded: bool, cumulative_gas: u64, logs: Vec<Log>) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

fn make_simple_tx() -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: 21000,
        to: TxKind::Call(Address::zero()),
        ..Default::default()
    })
}

fn test_store() -> Store {
    Store::new("", EngineType::InMemory).expect("in-memory store")
}

#[test]
fn test_service_creation_and_shutdown() {
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

    assert!(service.is_running());
    service.shutdown();

    // Give the worker thread time to process shutdown
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!service.is_running());
}

#[test]
fn test_service_drop_joins_worker() {
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));
    assert!(service.is_running());

    // Drop should join the worker thread
    drop(service);
    // If we get here, the worker thread was successfully joined
}

#[test]
fn test_block_observer_trait_impl() {
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

    // Call on_block_committed via the BlockObserver trait
    let block = make_empty_block(1);
    let receipts = vec![];
    service.on_block_committed(block, receipts);

    // Should process without error (no suspicious TXs in empty block)
    // Give worker time to process
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(service.is_running());
}

#[test]
fn test_service_processes_benign_block_no_alerts() {
    let alert_count = Arc::new(AtomicUsize::new(0));
    let handler = CountingAlertHandler {
        count: alert_count.clone(),
    };

    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

    // Send a benign block with a simple TX and receipt
    let block = Block {
        header: BlockHeader {
            number: 1,
            gas_used: 21000,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        body: BlockBody {
            transactions: vec![make_simple_tx()],
            ..Default::default()
        },
    };
    let receipts = vec![make_receipt(true, 21000, vec![])];

    service.on_block_committed(block, receipts);

    // Give worker time to process
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Pre-filter should dismiss benign TX — no alerts
    assert_eq!(alert_count.load(Ordering::SeqCst), 0);
}

#[test]
fn test_service_multiple_blocks_sequential() {
    let alert_count = Arc::new(AtomicUsize::new(0));
    let handler = CountingAlertHandler {
        count: alert_count.clone(),
    };

    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

    // Send 5 empty blocks
    for i in 0..5 {
        let block = make_empty_block(i);
        service.on_block_committed(block, vec![]);
    }

    // Give worker time to process all
    std::thread::sleep(std::time::Duration::from_millis(100));

    // No suspicious TXs — zero alerts
    assert_eq!(alert_count.load(Ordering::SeqCst), 0);
    assert!(service.is_running());
}

#[test]
fn test_service_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SentinelService>();
}

#[test]
fn test_block_observer_dynamic_dispatch() {
    // Verify SentinelService can be used as Arc<dyn BlockObserver>
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

    let observer: Arc<dyn BlockObserver> = Arc::new(service);

    // Should be callable through the trait object
    let block = make_empty_block(42);
    observer.on_block_committed(block, vec![]);

    // Give worker time to process
    std::thread::sleep(std::time::Duration::from_millis(50));
}

#[test]
fn test_alert_handler_log_handler_doesnt_panic() {
    // Verify LogAlertHandler doesn't panic on alert
    let handler = LogAlertHandler;
    let alert = SentinelAlert {
        block_number: 123,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: crate::sentinel::types::AlertPriority::High,
        suspicion_reasons: vec![],
        suspicion_score: 0.6,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        whitelist_matches: 0,
        summary: "Test alert".to_string(),
        total_steps: 100,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };

    handler.on_alert(alert);
}

#[test]
fn test_service_shutdown_idempotent() {
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

    // Multiple shutdowns should not panic
    service.shutdown();
    service.shutdown();
    service.shutdown();

    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(!service.is_running());
}

#[test]
fn test_service_send_after_shutdown() {
    let store = test_store();
    let config = SentinelConfig::default();
    let analysis_config = AnalysisConfig::default();

    let service = SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

    service.shutdown();
    std::thread::sleep(std::time::Duration::from_millis(50));

    // Sending after shutdown should not panic (silently drops)
    let block = make_empty_block(1);
    service.on_block_committed(block, vec![]);
}

#[test]
fn test_counting_alert_handler() {
    let count = Arc::new(AtomicUsize::new(0));
    let handler = CountingAlertHandler {
        count: count.clone(),
    };

    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: crate::sentinel::types::AlertPriority::Medium,
        suspicion_reasons: vec![],
        suspicion_score: 0.4,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        whitelist_matches: 0,
        summary: "Test".to_string(),
        total_steps: 0,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };

    handler.on_alert(alert.clone());
    handler.on_alert(alert.clone());
    handler.on_alert(alert);

    assert_eq!(count.load(Ordering::SeqCst), 3);
}

// ---------------------------------------------------------------------------
// Reentrancy Sentinel E2E tests
// ---------------------------------------------------------------------------

mod reentrancy_sentinel_e2e_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use ethrex_common::types::{
        Block, BlockBody, BlockHeader, LegacyTransaction, Receipt, Transaction, TxKind, TxType,
    };
    use ethrex_common::{Address, U256};
    use ethrex_storage::{EngineType, Store};

    use crate::sentinel::service::{AlertHandler, SentinelService};
    use crate::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelConfig};

    struct CountingAlertHandler {
        count: Arc<AtomicUsize>,
        last_score: Arc<std::sync::Mutex<f64>>,
    }

    impl AlertHandler for CountingAlertHandler {
        fn on_alert(&self, alert: SentinelAlert) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut s) = self.last_score.lock() {
                *s = alert.suspicion_score;
            }
        }
    }

    #[test]
    fn reentrancy_sentinel_service_e2e_alert() {
        let alert_count = Arc::new(AtomicUsize::new(0));
        let last_score = Arc::new(std::sync::Mutex::new(0.0_f64));
        let handler = CountingAlertHandler {
            count: alert_count.clone(),
            last_score: last_score.clone(),
        };

        let store = Store::new("", EngineType::InMemory).expect("in-memory store");
        let config = SentinelConfig::default(); // threshold 0.5

        // Enable prefilter_alert_mode so alerts emit even without deep analysis
        let analysis_config = AnalysisConfig {
            prefilter_alert_mode: true,
            ..Default::default()
        };

        let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

        // Build a block with a suspicious TX: 5 ETH + reverted + high gas + no logs
        // H2 = 0.3, H6 = 0.3 → total 0.6 >= 0.5
        let five_eth = U256::from(5_000_000_000_000_000_000_u64);
        let tx = Transaction::LegacyTransaction(LegacyTransaction {
            gas: 3_000_000,
            to: TxKind::Call(Address::from_low_u64_be(0xDEAD)),
            value: five_eth,
            data: Bytes::new(),
            ..Default::default()
        });
        let receipt = Receipt {
            tx_type: TxType::Legacy,
            succeeded: false,
            cumulative_gas_used: 2_000_000,
            logs: vec![],
        };

        let block = Block {
            header: BlockHeader {
                number: 19_500_000,
                gas_used: 2_000_000,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            body: BlockBody {
                transactions: vec![tx],
                ..Default::default()
            },
        };

        // Feed the block through BlockObserver
        use ethrex_blockchain::BlockObserver;
        service.on_block_committed(block, vec![receipt]);

        // Wait for the worker thread to process
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Verify alert was emitted via prefilter fallback
        let count = alert_count.load(Ordering::SeqCst);
        assert!(
            count >= 1,
            "Expected at least 1 alert from prefilter_alert_mode, got {count}"
        );

        // Verify alert score
        let score = *last_score.lock().unwrap();
        assert!(
            score >= 0.5,
            "Alert suspicion_score should be >= 0.5, got {score}"
        );

        // Verify metrics
        let metrics = service.metrics();
        let snap = metrics.snapshot();
        assert!(
            snap.txs_flagged >= 1,
            "Expected txs_flagged >= 1, got {}",
            snap.txs_flagged
        );
        assert!(
            snap.alerts_emitted >= 1,
            "Expected alerts_emitted >= 1, got {}",
            snap.alerts_emitted
        );
    }
}
