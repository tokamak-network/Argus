//! Tests for RpcSentinelService and its alert-builder helpers.

use std::sync::Arc;
use std::time::Duration;

use crate::autopsy::rpc_client::{RpcBlock, RpcBlockHeader, RpcReceipt, RpcTransaction};
use crate::sentinel::pre_filter::PreFilter;
use crate::sentinel::rpc_service::{
    ProcessContext, RpcSentinelConfig, RpcSentinelService, build_deep_alert, build_prefilter_alert,
    process_rpc_block,
};
use crate::sentinel::types::{AlertPriority, AnalysisConfig, SentinelConfig, SuspicionReason, SuspiciousTx};
use crate::sentinel::metrics::SentinelMetrics;
use ethrex_common::{Address, H256, U256};
use tokio::sync::mpsc;

fn make_rpc_block_header(number: u64) -> RpcBlockHeader {
    RpcBlockHeader {
        hash: H256::from_low_u64_be(number),
        number,
        timestamp: 1_700_000_000 + number,
        gas_limit: 30_000_000,
        base_fee_per_gas: Some(1_000_000_000),
        coinbase: Address::from_low_u64_be(0x01),
    }
}

fn make_rpc_block(number: u64) -> RpcBlock {
    RpcBlock {
        header: make_rpc_block_header(number),
        transactions: vec![],
    }
}

// --- Configuration tests ---

#[test]
fn test_rpc_sentinel_config_defaults() {
    let config = RpcSentinelConfig::default();
    assert_eq!(config.rpc_url, "http://localhost:8545");
    assert!(!config.prefilter_only);
    assert!(config.analysis_config.prefilter_alert_mode);
    assert_eq!(config.analysis_config.max_steps, 1_000_000);
}

#[test]
fn test_rpc_sentinel_config_new() {
    let config = RpcSentinelConfig::new("https://mainnet.infura.io/v3/KEY");
    assert_eq!(config.rpc_url, "https://mainnet.infura.io/v3/KEY");
    assert_eq!(
        config.poller_config.rpc_url,
        "https://mainnet.infura.io/v3/KEY"
    );
}

#[test]
fn test_rpc_sentinel_config_prefilter_only() {
    let mut config = RpcSentinelConfig::default();
    config.prefilter_only = true;
    assert!(config.prefilter_only);
}

// --- Service lifecycle tests ---

#[tokio::test]
async fn test_service_lifecycle() {
    let (alert_tx, _alert_rx) = mpsc::channel(16);
    let mut config = RpcSentinelConfig::default();
    config.rpc_url = "http://127.0.0.1:19998".into();
    config.poller_config = crate::sentinel::rpc_poller::RpcPollerConfig {
        rpc_url: "http://127.0.0.1:19998".into(),
        poll_interval: Duration::from_millis(50),
        rpc_config: crate::autopsy::rpc_client::RpcConfig {
            timeout: Duration::from_millis(100),
            connect_timeout: Duration::from_millis(100),
            max_retries: 0,
            base_backoff: Duration::from_millis(10),
        },
    };

    let service = RpcSentinelService::start(config, alert_tx).await;
    let snapshot = service.metrics().snapshot();
    assert_eq!(snapshot.blocks_scanned, 0);
    service.shutdown().await;
}

#[tokio::test]
async fn test_service_metrics_accessible() {
    let (alert_tx, _alert_rx) = mpsc::channel(16);
    let config = RpcSentinelConfig::default();
    let service = RpcSentinelService::start(config, alert_tx).await;
    let metrics = service.metrics();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.alerts_emitted, 0);
    assert_eq!(snapshot.txs_scanned, 0);
    service.shutdown().await;
}

// --- Prefilter-only mode: no deep replay alerts ---

#[tokio::test]
async fn test_prefilter_only_skips_deep_replay() {
    // In prefilter_only mode, a suspicious TX must emit an alert without needing an
    // archive RPC. This test uses a dead RPC URL — if deep replay were attempted it
    // would time out and potentially emit a data_quality=Low alert instead. We verify
    // that exactly one alert is emitted (the lightweight prefilter kind) even though the
    // rpc_url points to nothing.
    let (alert_tx, mut alert_rx) = mpsc::channel(16);
    let metrics = Arc::new(SentinelMetrics::new());

    let tx = RpcTransaction {
        hash: H256::from_low_u64_be(0xABCD),
        from: Address::from_low_u64_be(0x100),
        to: Some(Address::from_low_u64_be(0x42)),
        value: U256::from(2_000_000_000_000_000_000_u64), // 2 ETH
        input: vec![],
        gas: 600_000,
        gas_price: Some(2_000_000_000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        nonce: 0,
        block_number: Some(42),
    };
    let rpc_block = RpcBlock {
        header: make_rpc_block_header(42),
        transactions: vec![tx],
    };
    let receipt = RpcReceipt {
        status: false,
        cumulative_gas_used: 550_000,
        logs: vec![],
        transaction_hash: H256::from_low_u64_be(0xABCD),
        transaction_index: 0,
        gas_used: 550_000,
    };

    let sentinel_config = crate::sentinel::types::SentinelConfig {
        min_gas_used: 500_000,
        min_value_wei: U256::from(1_000_000_000_000_000_000_u64),
        suspicion_threshold: 0.25,
        min_independent_signals: 1,
        ..Default::default()
    };
    let pre_filter = crate::sentinel::pre_filter::PreFilter::new(sentinel_config);
    let analysis_config = crate::sentinel::types::AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    // prefilter_only=true — even a dead rpc_url must not block alert emission
    process_rpc_block(
        &rpc_block,
        &[receipt],
        ProcessContext::new_for_test(
            &pre_filter,
            "http://127.0.0.1:1", // unreachable — must not be contacted in prefilter_only mode
            &analysis_config,
            true,
            &alert_tx,
            &metrics,
        ),
    )
    .await;

    drop(alert_tx);
    let alert = alert_rx.recv().await.expect("expected prefilter alert");
    assert_eq!(alert.block_number, 42);
    assert!(
        alert.summary.contains("Pre-filter alert (RPC)"),
        "expected prefilter summary, got: {}",
        alert.summary
    );
    // Deep replay was skipped — detected_patterns must be empty
    assert!(
        alert.detected_patterns.is_empty(),
        "prefilter_only alerts must not have detected_patterns"
    );
}

// --- Alert emission test (synthetic, offline) ---

#[tokio::test]
async fn test_alert_emission_prefilter_only() {
    let (alert_tx, mut alert_rx) = mpsc::channel(16);
    let metrics = Arc::new(SentinelMetrics::new());

    let high_value = U256::from(2_000_000_000_000_000_000_u64); // 2 ETH
    let tx = RpcTransaction {
        hash: H256::from_low_u64_be(0x1234),
        from: Address::from_low_u64_be(0x100),
        to: Some(Address::from_low_u64_be(0x42)),
        value: high_value,
        input: vec![],
        gas: 600_000,
        gas_price: Some(2_000_000_000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        nonce: 0,
        block_number: Some(100),
    };
    let rpc_block = RpcBlock {
        header: make_rpc_block_header(100),
        transactions: vec![tx],
    };
    let receipt = RpcReceipt {
        status: false,
        cumulative_gas_used: 550_000,
        logs: vec![],
        transaction_hash: H256::from_low_u64_be(0x1234),
        transaction_index: 0,
        gas_used: 550_000,
    };

    let sentinel_config = SentinelConfig {
        min_gas_used: 500_000,
        min_value_wei: U256::from(1_000_000_000_000_000_000_u64),
        suspicion_threshold: 0.25,
        min_independent_signals: 1,
        ..Default::default()
    };
    let pre_filter = PreFilter::new(sentinel_config);
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    process_rpc_block(
        &rpc_block,
        &[receipt],
        ProcessContext::new_for_test(
            &pre_filter,
            "http://127.0.0.1:1",
            &analysis_config,
            true,
            &alert_tx,
            &metrics,
        ),
    )
    .await;

    drop(alert_tx);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.blocks_scanned, 1);
    assert_eq!(snapshot.txs_scanned, 1);
    assert!(
        snapshot.txs_flagged > 0,
        "expected TX to be flagged by pre-filter"
    );
    let alert = alert_rx.recv().await.expect("expected alert");
    assert_eq!(alert.block_number, 100);
    assert_eq!(alert.tx_index, 0);
    assert_eq!(snapshot.alerts_emitted, 1);
}

// --- Deep replay failure → prefilter_alert_mode fallback ---

#[tokio::test]
async fn test_deep_replay_failure_emits_low_quality_alert() {
    // prefilter_only=false but rpc_url is unreachable → replay fails.
    // With prefilter_alert_mode=true the service must fall back to a prefilter alert
    // with DataQuality::Low instead of silently dropping it.
    let (alert_tx, mut alert_rx) = mpsc::channel(16);
    let metrics = Arc::new(SentinelMetrics::new());

    let tx = RpcTransaction {
        hash: H256::from_low_u64_be(0xDEAD),
        from: Address::from_low_u64_be(0x200),
        to: Some(Address::from_low_u64_be(0x42)),
        value: U256::from(2_000_000_000_000_000_000_u64), // 2 ETH
        input: vec![],
        gas: 600_000,
        gas_price: Some(2_000_000_000),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        nonce: 1,
        block_number: Some(999),
    };
    let rpc_block = RpcBlock {
        header: make_rpc_block_header(999),
        transactions: vec![tx],
    };
    let receipt = RpcReceipt {
        status: false,
        cumulative_gas_used: 550_000,
        logs: vec![],
        transaction_hash: H256::from_low_u64_be(0xDEAD),
        transaction_index: 0,
        gas_used: 550_000,
    };

    let sentinel_config = crate::sentinel::types::SentinelConfig {
        min_gas_used: 500_000,
        min_value_wei: U256::from(1_000_000_000_000_000_000_u64),
        suspicion_threshold: 0.25,
        min_independent_signals: 1,
        ..Default::default()
    };
    let pre_filter = crate::sentinel::pre_filter::PreFilter::new(sentinel_config);
    // prefilter_alert_mode=true → failed replay must emit fallback alert
    let analysis_config = crate::sentinel::types::AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    process_rpc_block(
        &rpc_block,
        &[receipt],
        ProcessContext::new_for_test(
            &pre_filter,
            "http://127.0.0.1:1", // unreachable — replay must fail
            &analysis_config,
            false, // prefilter_only=false → deep replay attempted
            &alert_tx,
            &metrics,
        ),
    )
    .await;

    drop(alert_tx);
    let alert = alert_rx.recv().await.expect("expected fallback alert on replay failure");
    assert_eq!(alert.block_number, 999);
    assert_eq!(
        alert.data_quality,
        Some(crate::types::DataQuality::Low),
        "replay failure with prefilter_alert_mode must produce DataQuality::Low"
    );
}

// --- Alert builder tests ---

#[test]
fn test_build_prefilter_alert_fields() {
    let rpc_block = make_rpc_block(42);
    let suspicion = SuspiciousTx {
        tx_hash: H256::from_low_u64_be(0xbeef),
        tx_index: 3,
        reasons: vec![SuspicionReason::SelfDestructDetected],
        score: 0.8,
        priority: AlertPriority::High,
        whitelist_matches: 0,
    };

    let alert = build_prefilter_alert(&rpc_block, &suspicion);
    assert_eq!(alert.block_number, 42);
    assert_eq!(alert.tx_index, 3);
    assert_eq!(alert.tx_hash, H256::from_low_u64_be(0xbeef));
    assert_eq!(alert.suspicion_score, 0.8);
    assert!(alert.summary.contains("Pre-filter alert (RPC)"));
    assert!(alert.summary.contains("self-destruct"));
}

#[test]
fn test_build_deep_alert_fields() {
    let rpc_block = make_rpc_block(100);
    let suspicion = SuspiciousTx {
        tx_hash: H256::from_low_u64_be(0xcafe),
        tx_index: 1,
        reasons: vec![SuspicionReason::MultipleErc20Transfers { count: 10 }],
        score: 0.75,
        priority: AlertPriority::High,
        whitelist_matches: 0,
    };

    let empty_steps: Vec<crate::types::StepRecord> = Vec::new();
    let alert = build_deep_alert(&rpc_block, &suspicion, &empty_steps, true);
    assert_eq!(alert.block_number, 100);
    assert_eq!(alert.total_steps, 0);
    assert!(alert.summary.contains("Deep RPC alert"));
    assert!(alert.summary.contains("steps=0"));
    assert!(alert.summary.contains("success=true"));
    assert!(alert.summary.contains("erc20-transfers"));
}

fn make_reentrancy_steps() -> Vec<crate::types::StepRecord> {
    let victim = Address::from_low_u64_be(0x01C);
    let attacker = Address::from_low_u64_be(0xA77);
    let attacker_u256 = U256::from_big_endian(attacker.as_bytes());
    let victim_u256 = U256::from_big_endian(victim.as_bytes());

    vec![
        crate::types::StepRecord {
            step_index: 0,
            pc: 0,
            opcode: 0xF1,
            depth: 0,
            gas_remaining: 1_000_000,
            stack_top: vec![U256::zero(), attacker_u256, U256::from(1_000)],
            stack_depth: 7,
            memory_size: 0,
            code_address: victim,
            call_value: Some(U256::from(1_000)),
            storage_writes: None,
            log_topics: None,
            log_data: None,
            call_input_selector: None,
        },
        crate::types::StepRecord {
            step_index: 1,
            pc: 0,
            opcode: 0xF1,
            depth: 1,
            gas_remaining: 900_000,
            stack_top: vec![U256::zero(), victim_u256, U256::zero()],
            stack_depth: 7,
            memory_size: 0,
            code_address: attacker,
            call_value: None,
            storage_writes: None,
            log_topics: None,
            log_data: None,
            call_input_selector: None,
        },
        crate::types::StepRecord {
            step_index: 2,
            pc: 10,
            opcode: 0x55,
            depth: 2,
            gas_remaining: 800_000,
            stack_top: vec![U256::from(1), U256::zero()],
            stack_depth: 2,
            memory_size: 0,
            code_address: victim,
            call_value: None,
            storage_writes: Some(vec![crate::types::StorageWrite {
                address: victim,
                slot: H256::zero(),
                old_value: U256::zero(),
                new_value: U256::from(1),
            }]),
            log_topics: None,
            log_data: None,
            call_input_selector: None,
        },
    ]
}

#[test]
fn test_build_deep_alert_populates_detected_patterns_from_steps() {
    let rpc_block = make_rpc_block(200);
    let suspicion = SuspiciousTx {
        tx_hash: H256::from_low_u64_be(0xdead),
        tx_index: 0,
        reasons: vec![SuspicionReason::SelfDestructDetected],
        score: 0.9,
        priority: AlertPriority::Critical,
        whitelist_matches: 0,
    };

    let steps = make_reentrancy_steps();
    let alert = build_deep_alert(&rpc_block, &suspicion, &steps, true);
    assert!(
        !alert.detected_patterns.is_empty(),
        "deep alert should populate detected_patterns from replay steps"
    );
}

#[test]
fn test_build_deep_alert_populates_fund_flows_from_steps() {
    let rpc_block = make_rpc_block(201);
    let suspicion = SuspiciousTx {
        tx_hash: H256::from_low_u64_be(0xbeef),
        tx_index: 0,
        reasons: vec![SuspicionReason::SelfDestructDetected],
        score: 0.9,
        priority: AlertPriority::Critical,
        whitelist_matches: 0,
    };

    let steps = make_reentrancy_steps();
    let alert = build_deep_alert(&rpc_block, &suspicion, &steps, true);
    assert!(
        !alert.fund_flows.is_empty(),
        "deep alert should populate fund_flows from replay steps"
    );
}
