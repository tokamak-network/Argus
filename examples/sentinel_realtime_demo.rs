//! Sentinel Real-Time Detection Demo
//!
//! Demonstrates the full Sentinel feature set for real-time hack detection:
//!
//!   Demo 1: Multi-TX Block Scanning (benign + suspicious transactions)
//!   Demo 2: Alert Pipeline (Dispatcher → Deduplicator → RateLimiter)
//!   Demo 3: Mempool Pre-Filter (calldata heuristic scanning)
//!   Demo 4: Auto-Pause Circuit Breaker (PauseController integration)
//!   Demo 5: Prometheus Metrics Exposition
//!   Demo 6: TOML Configuration Loading
//!
//! Run: cargo run -p argus --features sentinel --example sentinel_realtime_demo

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ethrex_blockchain::{BlockObserver, MempoolObserver, PauseController};
use ethrex_common::types::{
    Block, BlockBody, BlockHeader, EIP1559Transaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};
use ethrex_storage::{EngineType, Store};

use argus::sentinel::alert::{
    AlertDeduplicator, AlertDispatcher, AlertRateLimiter, JsonlFileAlertHandler,
};
use argus::sentinel::auto_pause::AutoPauseHandler;
use argus::sentinel::config::{MempoolMonitorConfig, SentinelFullConfig};
use argus::sentinel::service::{AlertHandler, SentinelService};
use argus::sentinel::types::{
    AlertPriority, AnalysisConfig, SentinelAlert, SentinelConfig,
};

// ── Collecting Alert Handler ─────────────────────────────────────────────

/// Captures all alerts for later inspection.
struct CollectingHandler {
    count: Arc<AtomicUsize>,
    alerts: Arc<Mutex<Vec<SentinelAlert>>>,
}

impl CollectingHandler {
    fn new() -> (Self, Arc<AtomicUsize>, Arc<Mutex<Vec<SentinelAlert>>>) {
        let count = Arc::new(AtomicUsize::new(0));
        let alerts = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                count: count.clone(),
                alerts: alerts.clone(),
            },
            count,
            alerts,
        )
    }
}

impl AlertHandler for CollectingHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        self.count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut v) = self.alerts.lock() {
            v.push(alert);
        }
    }
}

// ── Block/TX Builders ────────────────────────────────────────────────────

/// ERC-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
fn transfer_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xdd;
    bytes[1] = 0xf2;
    bytes[2] = 0x52;
    bytes[3] = 0xad;
    H256::from(bytes)
}

/// Aave V2 FlashLoan event topic (simplified)
fn flash_loan_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x63;
    bytes[1] = 0x1c;
    bytes[2] = 0x02;
    bytes[3] = 0x4d;
    H256::from(bytes)
}

/// Known Aave V2 lending pool address
fn aave_v2_address() -> Address {
    let bytes =
        hex::decode("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9").expect("valid hex address");
    Address::from_slice(&bytes)
}

/// Build a benign transaction (simple ETH transfer, low gas)
fn benign_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0xBEEF)),
        value: U256::from(1_000_000_000_000_000_000_u64), // 1 ETH
        gas_limit: 21_000,
        data: Bytes::new(),
        ..Default::default()
    })
}

/// Build a benign receipt
fn benign_receipt(gas_used: u64) -> Receipt {
    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: true,
        cumulative_gas_used: gas_used,
        logs: vec![],
    }
}

/// Build a suspicious flash-loan TX (high gas, interacts with Aave)
fn flash_loan_tx() -> Transaction {
    // Aave flashLoan selector: 0xab9c4b5d
    let calldata = vec![0xab, 0x9c, 0x4b, 0x5d, 0x00, 0x00, 0x00, 0x00];
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(aave_v2_address()),
        gas_limit: 3_000_000,
        data: Bytes::from(calldata),
        ..Default::default()
    })
}

/// Build a receipt with flash loan + multiple ERC-20 transfers
fn flash_loan_receipt(cumulative_gas: u64, _gas_used: u64) -> Receipt {
    let mut logs = Vec::new();

    // Flash loan event from Aave
    logs.push(Log {
        address: aave_v2_address(),
        topics: vec![flash_loan_topic()],
        data: Bytes::from(vec![0u8; 64]),
    });

    // 6 ERC-20 Transfer events (triggers MultipleErc20Transfers heuristic)
    for i in 0..6 {
        logs.push(Log {
            address: Address::from_low_u64_be(0xDA10 + i),
            topics: vec![
                transfer_topic(),
                H256::from_low_u64_be(0x1000 + i), // from
                H256::from_low_u64_be(0x2000 + i), // to
            ],
            data: Bytes::from(vec![0u8; 32]), // amount
        });
    }

    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: true,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

/// Build a suspicious high-gas reverted TX
fn reverted_high_gas_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0xDEAD)),
        value: U256::from(5_000_000_000_000_000_000_u64), // 5 ETH
        gas_limit: 1_000_000,
        data: Bytes::new(),
        ..Default::default()
    })
}

/// Build a reverted receipt with high gas usage
fn reverted_receipt(cumulative_gas: u64, _gas_used: u64) -> Receipt {
    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: false,
        cumulative_gas_used: cumulative_gas,
        logs: vec![],
    }
}

/// Build a block with mixed transactions
fn build_mixed_block(block_number: u64, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            number: block_number,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        body: BlockBody {
            transactions: txs,
            ..Default::default()
        },
    }
}

// ── Demo Functions ───────────────────────────────────────────────────────

fn demo_1_multi_tx_scanning() {
    println!("Demo 1  Multi-TX Block Scanning");
    println!("----------------------------------------------------------------");
    println!("  Scenario: Block with 3 TXs — 1 benign, 1 flash-loan, 1 reverted");
    println!();

    let (handler, count, alerts) = CollectingHandler::new();
    let store = Store::new("", EngineType::InMemory).expect("in-memory store");

    let config = SentinelConfig {
        suspicion_threshold: 0.1, // Low threshold to catch all suspicious activity
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true, // Emit alerts without deep analysis state
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

    let block = build_mixed_block(
        18_000_001,
        vec![benign_tx(), flash_loan_tx(), reverted_high_gas_tx()],
    );
    let receipts = vec![
        benign_receipt(21_000),
        flash_loan_receipt(2_521_000, 2_500_000),
        reverted_receipt(3_471_000, 950_000),
    ];

    println!("  TX 0: Simple ETH transfer (21k gas, success)");
    println!("  TX 1: Flash loan via Aave (2.5M gas, 6 ERC-20 transfers)");
    println!("  TX 2: 5 ETH transfer, reverted (950k gas)");
    println!();

    service.on_block_committed(block, receipts);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let alert_count = count.load(Ordering::SeqCst);
    println!("  Results:");
    println!("    Alerts emitted: {alert_count}");

    if let Ok(captured) = alerts.lock() {
        for (i, alert) in captured.iter().enumerate() {
            println!("    Alert #{i}:");
            println!("      Block:    #{}", alert.block_number);
            println!("      TX index: {}", alert.tx_index);
            println!("      Priority: {:?}", alert.alert_priority);
            println!("      Score:    {:.2}", alert.suspicion_score);
            println!("      Summary:  {}", alert.summary);
            for r in &alert.suspicion_reasons {
                println!("      Reason:   {r:?}");
            }
        }
    }

    let snap = service.metrics().snapshot();
    println!();
    println!("    Metrics: scanned={} txs, flagged={}, alerts={}",
        snap.txs_scanned, snap.txs_flagged, snap.alerts_emitted);

    service.shutdown();
    println!();
}

fn demo_2_alert_pipeline() {
    println!("Demo 2  Alert Pipeline (Dispatcher + Deduplicator + RateLimiter)");
    println!("----------------------------------------------------------------");
    println!("  Scenario: 5 blocks, some with duplicate patterns");
    println!();

    let (handler, count, _alerts) = CollectingHandler::new();

    // Build composable pipeline: RateLimiter → Deduplicator → Dispatcher
    let jsonl_path = std::env::temp_dir().join("sentinel_demo_alerts.jsonl");
    let _ = std::fs::remove_file(&jsonl_path);

    let mut dispatcher = AlertDispatcher::default();
    dispatcher.add_handler(Box::new(handler));
    dispatcher.add_handler(Box::new(JsonlFileAlertHandler::new(jsonl_path.clone())));

    let dedup = AlertDeduplicator::new(Box::new(dispatcher), 3); // 3-block window
    let limiter = AlertRateLimiter::new(Box::new(dedup), 10);

    let store = Store::new("", EngineType::InMemory).expect("store");
    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(limiter));

    // Feed 5 blocks with similar flash-loan TXs
    for block_num in 100..105 {
        let block = build_mixed_block(block_num, vec![flash_loan_tx()]);
        let receipts = vec![flash_loan_receipt(2_500_000, 2_500_000)];

        service.on_block_committed(block, receipts);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let alert_count = count.load(Ordering::SeqCst);
    println!("  5 blocks fed, each with 1 flash-loan TX");
    println!("  Dedup window: 3 blocks | Rate limit: 10/min");
    println!();
    println!("  Alerts received by final handler: {alert_count}");
    println!("  (Expected: <5 due to deduplication within 3-block window)");

    // Check JSONL file
    if let Ok(content) = std::fs::read_to_string(&jsonl_path) {
        let lines: Vec<&str> = content.lines().collect();
        println!("  JSONL file lines: {}", lines.len());
    }

    let _ = std::fs::remove_file(&jsonl_path);
    service.shutdown();
    println!();
}

fn demo_3_mempool_monitoring() {
    println!("Demo 3  Mempool Pre-Filter (Pending TX Scanning)");
    println!("----------------------------------------------------------------");
    println!("  Scenario: 4 pending TXs scanned before block inclusion");
    println!();

    let (handler, count, _alerts) = CollectingHandler::new();
    let store = Store::new("", EngineType::InMemory).expect("store");

    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };
    let mempool_config = MempoolMonitorConfig {
        enabled: true,
        min_value_eth: 0.1,  // Low threshold for demo
        min_gas: 100_000,
    };

    let service = SentinelService::with_mempool(
        store,
        config,
        analysis_config,
        Box::new(handler),
        Some(mempool_config),
    );

    let sender = Address::from_low_u64_be(0xABCD);

    // TX 1: Benign small transfer
    let tx1 = benign_tx();
    let hash1 = H256::from_low_u64_be(0x1111);
    println!("  TX 1: Simple transfer (21k gas) — expected: PASS (benign)");
    service.on_transaction_added(&tx1, sender, hash1);

    // TX 2: Flash loan calldata targeting Aave
    let tx2 = flash_loan_tx();
    let hash2 = H256::from_low_u64_be(0x2222);
    println!("  TX 2: Flash loan selector to Aave (3M gas) — expected: FLAGGED");
    service.on_transaction_added(&tx2, sender, hash2);

    // TX 3: High-value TX to known DeFi contract
    let tx3 = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(aave_v2_address()),
        value: U256::from(50_000_000_000_000_000_000_u128), // 50 ETH
        gas_limit: 800_000,
        data: Bytes::new(),
        ..Default::default()
    });
    let hash3 = H256::from_low_u64_be(0x3333);
    println!("  TX 3: 50 ETH to Aave (800k gas) — expected: FLAGGED");
    service.on_transaction_added(&tx3, sender, hash3);

    // TX 4: Large contract creation
    let tx4 = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Create,
        gas_limit: 5_000_000,
        data: Bytes::from(vec![0x60; 15_000]), // 15KB init code
        ..Default::default()
    });
    let hash4 = H256::from_low_u64_be(0x4444);
    println!("  TX 4: Contract creation (15KB init code) — expected: FLAGGED");
    service.on_transaction_added(&tx4, sender, hash4);

    std::thread::sleep(std::time::Duration::from_millis(500));

    let snap = service.metrics().snapshot();
    println!();
    println!("  Results:");
    println!("    Mempool TXs scanned:  {}", snap.mempool_txs_scanned);
    println!("    Mempool TXs flagged:  {}", snap.mempool_txs_flagged);
    println!("    Mempool alerts:       {}", snap.mempool_alerts_emitted);
    println!("    Handler alert count:  {}", count.load(Ordering::SeqCst));

    service.shutdown();
    println!();
}

fn demo_4_auto_pause() {
    println!("Demo 4  Auto-Pause Circuit Breaker");
    println!("----------------------------------------------------------------");
    println!("  Scenario: Critical alert triggers automatic block processing halt");
    println!();

    let pause_controller = Arc::new(PauseController::new(Some(10))); // 10s auto-resume
    println!("  PauseController created (auto-resume: 10s)");
    println!("  Initial state: paused={}", pause_controller.is_paused());

    // Build handler chain: AutoPause + Collecting
    let (collector, count, _alerts) = CollectingHandler::new();
    let auto_pause = AutoPauseHandler::with_thresholds(
        pause_controller.clone(),
        0.7,                    // confidence threshold
        AlertPriority::High,    // trigger on High or above
    );
    let mut dispatcher = AlertDispatcher::default();
    dispatcher.add_handler(Box::new(collector));
    dispatcher.add_handler(Box::new(auto_pause));

    let store = Store::new("", EngineType::InMemory).expect("store");
    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(dispatcher));

    // Feed a block with a suspicious flash-loan TX (should score high enough)
    let block = build_mixed_block(
        19_000_000,
        vec![flash_loan_tx()],
    );
    let receipts = vec![flash_loan_receipt(2_500_000, 2_500_000)];

    println!("  Feeding suspicious block #19000000...");
    service.on_block_committed(block, receipts);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let paused_after = pause_controller.is_paused();
    let alert_count = count.load(Ordering::SeqCst);
    println!();
    println!("  After block processing:");
    println!("    Alerts emitted:  {alert_count}");
    println!("    Chain paused:    {paused_after}");

    if paused_after {
        println!("    Auto-resume in:  {:?}s",
            pause_controller.auto_resume_remaining());
        println!();
        println!("  Simulating operator resume...");
        pause_controller.resume();
        println!("    Chain paused:    {}", pause_controller.is_paused());
    } else {
        println!("    (Score was below threshold — no pause triggered)");
        println!("    This is expected: pre-filter-only alerts may not reach 0.7 confidence");
    }

    service.shutdown();
    println!();
}

fn demo_5_prometheus_metrics() {
    println!("Demo 5  Prometheus Metrics Exposition");
    println!("----------------------------------------------------------------");
    println!("  Scenario: Process blocks then export metrics in Prometheus format");
    println!();

    let (handler, _count, _alerts) = CollectingHandler::new();
    let store = Store::new("", EngineType::InMemory).expect("store");

    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

    // Feed a few blocks
    for block_num in 1..4 {
        let block = build_mixed_block(
            block_num,
            vec![benign_tx(), flash_loan_tx()],
        );
        let receipts = vec![
            benign_receipt(21_000),
            flash_loan_receipt(2_521_000, 2_500_000),
        ];
        service.on_block_committed(block, receipts);
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    let prometheus_text = service.metrics().to_prometheus_text();

    // Show first 20 lines of Prometheus output
    println!("  Prometheus text exposition (first 20 lines):");
    for line in prometheus_text.lines().take(20) {
        println!("    {line}");
    }

    let snap = service.metrics().snapshot();
    println!();
    println!("  Snapshot summary:");
    println!("    blocks_scanned:       {}", snap.blocks_scanned);
    println!("    txs_scanned:          {}", snap.txs_scanned);
    println!("    txs_flagged:          {}", snap.txs_flagged);
    println!("    alerts_emitted:       {}", snap.alerts_emitted);
    println!("    prefilter_total_us:   {}us", snap.prefilter_total_us);
    println!("    deep_analysis_ms:     {}ms", snap.deep_analysis_total_ms);

    service.shutdown();
    println!();
}

fn demo_6_toml_config() {
    println!("Demo 6  TOML Configuration Loading");
    println!("----------------------------------------------------------------");
    println!("  Scenario: Load sentinel config from TOML, validate, and convert");
    println!();

    let toml_str = r#"
enabled = true

[prefilter]
suspicion_threshold = 0.3
min_value_eth = 0.5
min_gas_used = 300000
min_erc20_transfers = 3
gas_ratio_threshold = 0.90

[analysis]
max_steps = 500000
min_alert_confidence = 0.5
prefilter_alert_mode = true

[alert]
rate_limit_per_minute = 20
dedup_window_blocks = 5

[mempool]
enabled = true
min_value_eth = 5.0
min_gas = 300000

[auto_pause]
enabled = true
confidence_threshold = 0.8
priority_threshold = "Critical"
"#;

    println!("  TOML input:");
    for line in toml_str.trim().lines() {
        println!("    {line}");
    }
    println!();

    let config: SentinelFullConfig = toml::from_str(toml_str).expect("valid TOML");

    // Validate
    match config.validate() {
        Ok(()) => println!("  Validation: PASSED"),
        Err(e) => println!("  Validation FAILED: {e}"),
    }

    // Convert to domain types
    let sentinel_config = config.to_sentinel_config();
    let analysis_config = config.to_analysis_config();

    println!();
    println!("  Converted SentinelConfig:");
    println!("    suspicion_threshold: {}", sentinel_config.suspicion_threshold);
    println!("    min_value_wei:       {} (= {} ETH)",
        sentinel_config.min_value_wei,
        config.prefilter.min_value_eth);
    println!("    min_gas_used:        {}", sentinel_config.min_gas_used);
    println!();
    println!("  Converted AnalysisConfig:");
    println!("    max_steps:           {}", analysis_config.max_steps);
    println!("    min_alert_confidence:{}", analysis_config.min_alert_confidence);
    println!("    prefilter_alert_mode:{}", analysis_config.prefilter_alert_mode);
    println!();
    println!("  Mempool: enabled={}, min_value={}ETH, min_gas={}",
        config.mempool.enabled, config.mempool.min_value_eth, config.mempool.min_gas);
    println!("  AutoPause: enabled={}, threshold={}, priority={}",
        config.auto_pause.enabled,
        config.auto_pause.confidence_threshold,
        config.auto_pause.priority_threshold);
    println!();
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("================================================================");
    println!("  Sentinel Real-Time Detection — Feature Showcase");
    println!("================================================================");
    println!();

    demo_1_multi_tx_scanning();
    demo_2_alert_pipeline();
    demo_3_mempool_monitoring();
    demo_4_auto_pause();
    demo_5_prometheus_metrics();
    demo_6_toml_config();

    println!("================================================================");
    println!("  ALL 6 DEMOS COMPLETED");
    println!("================================================================");
    println!();
}
