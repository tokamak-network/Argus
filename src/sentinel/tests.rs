//! Tests for the Sentinel pre-filter engine and deep analysis types.

use bytes::Bytes;
use ethrex_common::types::{
    BlockHeader, LegacyTransaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};

use super::pre_filter::PreFilter;
use super::types::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn make_receipt(succeeded: bool, cumulative_gas: u64, logs: Vec<Log>) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

fn make_log(address: Address, topics: Vec<H256>, data: Bytes) -> Log {
    Log {
        address,
        topics,
        data,
    }
}

fn make_tx_call(to: Address, value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Call(to),
        value,
        ..Default::default()
    })
}

fn make_tx_create(value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Create,
        value,
        ..Default::default()
    })
}

fn make_header(number: u64) -> BlockHeader {
    BlockHeader {
        number,
        ..Default::default()
    }
}

fn random_address(seed: u8) -> Address {
    Address::from_slice(&[seed; 20])
}

/// Build an H256 topic with the given 4-byte prefix.
fn topic_with_prefix(prefix: [u8; 4]) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&prefix);
    H256::from(bytes)
}

/// Build a Transfer(address,address,uint256) topic.
fn transfer_topic() -> H256 {
    topic_with_prefix([0xdd, 0xf2, 0x52, 0xad])
}

/// Build a mock ERC-20 Transfer log with 3 topics.
fn make_erc20_transfer_log(from: Address, to: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..32].copy_from_slice(from.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..32].copy_from_slice(to.as_bytes());

    make_log(
        random_address(0xEE),
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]), // amount
    )
}

fn aave_v2_pool() -> Address {
    let bytes = hex::decode("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9").unwrap();
    Address::from_slice(&bytes)
}

fn uniswap_v3_router() -> Address {
    let bytes = hex::decode("E592427A0AEce92De3Edee1F18E0157C05861564").unwrap();
    Address::from_slice(&bytes)
}

fn chainlink_eth_usd() -> Address {
    let bytes = hex::decode("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419").unwrap();
    Address::from_slice(&bytes)
}

fn one_eth() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

// ---------------------------------------------------------------------------
// Config & types tests
// ---------------------------------------------------------------------------

#[test]
fn test_default_config() {
    let config = SentinelConfig::default();
    assert!((config.suspicion_threshold - 0.5).abs() < f64::EPSILON);
    assert_eq!(config.min_value_wei, one_eth());
    assert_eq!(config.min_gas_used, 500_000);
    assert_eq!(config.min_erc20_transfers, 5);
    assert!((config.gas_ratio_threshold - 0.95).abs() < f64::EPSILON);
}

#[test]
fn test_alert_priority_from_score() {
    assert_eq!(AlertPriority::from_score(0.0), AlertPriority::Medium);
    assert_eq!(AlertPriority::from_score(0.29), AlertPriority::Medium);
    assert_eq!(AlertPriority::from_score(0.49), AlertPriority::Medium);
    assert_eq!(AlertPriority::from_score(0.5), AlertPriority::High);
    assert_eq!(AlertPriority::from_score(0.79), AlertPriority::High);
    assert_eq!(AlertPriority::from_score(0.8), AlertPriority::Critical);
    assert_eq!(AlertPriority::from_score(1.0), AlertPriority::Critical);
}

#[test]
fn test_suspicion_reason_scores() {
    assert!(
        (SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero()
        }
        .score()
            - 0.4)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (SuspicionReason::HighValueWithRevert {
            value_wei: U256::zero(),
            gas_used: 0
        }
        .score()
            - 0.3)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (SuspicionReason::MultipleErc20Transfers { count: 7 }.score() - 0.2).abs() < f64::EPSILON
    );
    assert!(
        (SuspicionReason::MultipleErc20Transfers { count: 15 }.score() - 0.4).abs() < f64::EPSILON
    );
    assert!(
        (SuspicionReason::KnownContractInteraction {
            address: Address::zero(),
            label: String::new()
        }
        .score()
            - 0.1)
            .abs()
            < f64::EPSILON
    );
    assert!(
        (SuspicionReason::UnusualGasPattern {
            gas_used: 0,
            gas_limit: 0
        }
        .score()
            - 0.15)
            .abs()
            < f64::EPSILON
    );
    assert!((SuspicionReason::SelfDestructDetected.score() - 0.3).abs() < f64::EPSILON);
    assert!(
        (SuspicionReason::PriceOracleWithSwap {
            oracle: Address::zero()
        }
        .score()
            - 0.2)
            .abs()
            < f64::EPSILON
    );
}

#[test]
fn test_suspicious_tx_serialization() {
    let stx = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![SuspicionReason::SelfDestructDetected],
        score: 0.3,
        priority: AlertPriority::Medium,
    };
    let json = serde_json::to_string(&stx).unwrap();
    assert!(json.contains("SelfDestructDetected"));
    assert!(json.contains("\"score\":0.3"));
}

// ---------------------------------------------------------------------------
// Flash loan heuristic tests (H1)
// ---------------------------------------------------------------------------

#[test]
fn test_flash_loan_aave_topic_detected() {
    let filter = PreFilter::default();
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log = make_log(aave_v2_pool(), vec![aave_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::FlashLoanSignature { .. }))
    );
}

#[test]
fn test_flash_loan_balancer_detected() {
    let filter = PreFilter::default();
    let balancer_topic = topic_with_prefix([0x0d, 0x7d, 0x75, 0xe0]);
    let balancer_addr = {
        let bytes = hex::decode("BA12222222228d8Ba445958a75a0704d566BF2C8").unwrap();
        Address::from_slice(&bytes)
    };
    let log = make_log(balancer_addr, vec![balancer_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(balancer_addr, U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::FlashLoanSignature { .. }))
    );
}

#[test]
fn test_no_flash_loan_normal_tx() {
    let filter = PreFilter::default();
    let normal_topic = transfer_topic();
    let log = make_log(random_address(0x01), vec![normal_topic], Bytes::new());
    let receipt = make_receipt(true, 21_000, vec![log]);
    let tx = make_tx_call(random_address(0x02), U256::zero(), 50_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_flash_loan_uniswap_v3_detected() {
    let filter = PreFilter::default();
    let uni_topic = topic_with_prefix([0xbd, 0xbd, 0xb7, 0x16]);
    let log = make_log(random_address(0x33), vec![uni_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    // To address is also a known contract (Uniswap V3 Router) → +0.1 from H4
    let tx = make_tx_call(uniswap_v3_router(), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    assert!(result.unwrap().score >= 0.4);
}

// ---------------------------------------------------------------------------
// High value + revert tests (H2)
// ---------------------------------------------------------------------------

#[test]
fn test_high_value_revert_detected() {
    let filter = PreFilter::default();
    let receipt = make_receipt(false, 200_000, vec![]);
    let tx = make_tx_call(random_address(0x01), one_eth() * 2, 300_000);
    let header = make_header(19_500_000);

    // Score from H2 alone = 0.3, below default threshold 0.5 → not flagged
    // BUT with high gas and zero logs → H6 self-destruct might also fire if gas > 1M
    // With gas 200k, only H2 fires. Since 0.3 < 0.5, not suspicious.
    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none()); // 0.3 < 0.5 threshold
}

#[test]
fn test_high_value_revert_with_lower_threshold() {
    let config = SentinelConfig {
        suspicion_threshold: 0.2,
        ..Default::default()
    };
    let filter = PreFilter::new(config);
    let receipt = make_receipt(false, 200_000, vec![]);
    let tx = make_tx_call(random_address(0x01), one_eth() * 2, 300_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::HighValueWithRevert { .. }))
    );
    assert!((stx.score - 0.3).abs() < f64::EPSILON);
}

#[test]
fn test_high_value_success_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.2,
        ..Default::default()
    });
    let receipt = make_receipt(true, 200_000, vec![]);
    let tx = make_tx_call(random_address(0x01), one_eth() * 10, 300_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_low_value_revert_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.2,
        ..Default::default()
    });
    // Low value, reverted, but value < 1 ETH and no ERC-20 transfers
    let receipt = make_receipt(false, 200_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::from(1000), 300_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Multiple ERC-20 transfer tests (H3)
// ---------------------------------------------------------------------------

#[test]
fn test_many_erc20_transfers_moderate() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        ..Default::default()
    });
    // 7 Transfer events → score +0.2
    let logs: Vec<Log> = (0..7)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    let receipt = make_receipt(true, 500_000, logs);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::MultipleErc20Transfers { count: 7 }))
    );
}

#[test]
fn test_many_erc20_transfers_high() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    });
    // 15 Transfer events → score +0.4
    let logs: Vec<Log> = (0..15)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    let receipt = make_receipt(true, 500_000, logs);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(stx.score >= 0.4);
}

#[test]
fn test_few_erc20_transfers_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    // Only 2 transfers — below min_erc20_transfers (5)
    let logs: Vec<Log> = (0..2)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    let receipt = make_receipt(true, 21_000, logs);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 50_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Known contract tests (H4)
// ---------------------------------------------------------------------------

#[test]
fn test_known_contract_interaction_via_to() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.05,
        ..Default::default()
    });
    let receipt = make_receipt(true, 21_000, vec![]);
    let tx = make_tx_call(uniswap_v3_router(), U256::zero(), 50_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(stx.reasons.iter().any(|r| match r {
        SuspicionReason::KnownContractInteraction { label, .. } => label == "Uniswap V3 Router",
        _ => false,
    }));
}

#[test]
fn test_known_contract_in_logs() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.05,
        ..Default::default()
    });
    let log = make_log(chainlink_eth_usd(), vec![H256::zero()], Bytes::new());
    let receipt = make_receipt(true, 21_000, vec![log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 50_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(stx.reasons.iter().any(|r| match r {
        SuspicionReason::KnownContractInteraction { label, .. } => label == "Chainlink ETH/USD",
        _ => false,
    }));
}

#[test]
fn test_unknown_contract_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.05,
        ..Default::default()
    });
    let receipt = make_receipt(true, 21_000, vec![]);
    let tx = make_tx_call(random_address(0xFF), U256::zero(), 50_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Unusual gas pattern tests (H5)
// ---------------------------------------------------------------------------

#[test]
fn test_unusual_gas_pattern() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    // gas_used / gas_limit = 600k / 600k = 1.0 > 0.95, gas > 500k
    let receipt = make_receipt(true, 600_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 600_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::UnusualGasPattern { .. }))
    );
}

#[test]
fn test_normal_gas_pattern_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    // gas_used / gas_limit = 300k / 600k = 0.5 < 0.95
    let receipt = make_receipt(true, 300_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 600_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_low_gas_high_ratio_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    // gas_used / gas_limit = 21000 / 21000 = 1.0 > 0.95, but gas < 500k
    let receipt = make_receipt(true, 21_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 21_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Self-destruct tests (H6)
// ---------------------------------------------------------------------------

#[test]
fn test_self_destruct_indicators() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.2,
        ..Default::default()
    });
    // Reverted, high gas (>1M), empty logs
    let receipt = make_receipt(false, 2_000_000, vec![]);
    let tx = make_tx_call(random_address(0x01), one_eth() * 5, 3_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::SelfDestructDetected))
    );
}

#[test]
fn test_successful_tx_no_self_destruct() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    // Succeeded with empty logs — not self-destruct indicator
    let receipt = make_receipt(true, 2_000_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 3_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    // Only H5 might fire: 2M/3M = 0.67 < 0.95 → no
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Oracle + swap tests (H7)
// ---------------------------------------------------------------------------

#[test]
fn test_oracle_plus_dex_detected() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        ..Default::default()
    });
    let oracle_log = make_log(chainlink_eth_usd(), vec![H256::zero()], Bytes::new());
    let dex_log = make_log(uniswap_v3_router(), vec![H256::zero()], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![oracle_log, dex_log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::PriceOracleWithSwap { .. }))
    );
}

#[test]
fn test_oracle_only_not_flagged() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        ..Default::default()
    });
    let oracle_log = make_log(chainlink_eth_usd(), vec![H256::zero()], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![oracle_log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    // Only H4 fires for known contract: 0.1 < 0.15
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Integration / combined tests
// ---------------------------------------------------------------------------

#[test]
fn test_scan_block_empty() {
    let filter = PreFilter::default();
    let header = make_header(19_500_000);
    let result = filter.scan_block(&[], &[], &header);
    assert!(result.is_empty());
}

#[test]
fn test_scan_block_mixed() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // TX 0: benign simple transfer
    let tx0 = make_tx_call(random_address(0x01), U256::from(100), 21_000);
    let r0 = make_receipt(true, 21_000, vec![]);

    // TX 1: suspicious — flash loan topic
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log1 = make_log(aave_v2_pool(), vec![aave_topic], Bytes::new());
    let tx1 = make_tx_call(aave_v2_pool(), U256::zero(), 1_000_000);
    let r1 = make_receipt(true, 500_000, vec![log1]);

    // TX 2: benign create
    let tx2 = make_tx_create(U256::zero(), 100_000);
    let r2 = make_receipt(true, 50_000, vec![]);

    let txs = vec![tx0, tx1, tx2];
    let receipts = vec![r0, r1, r2];

    let result = filter.scan_block(&txs, &receipts, &header);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].tx_index, 1);
}

#[test]
fn test_combined_flash_loan_plus_transfers() {
    let filter = PreFilter::default(); // threshold = 0.5
    let header = make_header(19_500_000);

    // Flash loan topic + 7 ERC-20 transfers → 0.4 + 0.2 = 0.6 >= 0.5
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(aave_v2_pool(), vec![aave_topic], Bytes::new());
    let mut logs: Vec<Log> = (0..7)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs.insert(0, flash_log);

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(stx.score >= 0.5);
    assert_eq!(stx.priority, AlertPriority::High);
}

#[test]
fn test_threshold_boundary_exact() {
    // Score exactly at threshold → flagged
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.4,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan alone = 0.4 == threshold
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    // 0.4 >= 0.4 → not flagged because we use strict < comparison
    // Actually: `if score < self.config.suspicion_threshold` → 0.4 < 0.4 is false → flagged
    assert!(result.is_some());
}

#[test]
fn test_threshold_boundary_just_below() {
    // Score just below threshold → not flagged
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.5,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan alone = 0.4 < 0.5
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_critical_priority_combined() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan (0.4) + many ERC-20 transfers >10 (0.4) + known contract (0.1) = 0.9 → Critical
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(aave_v2_pool(), vec![aave_topic], Bytes::new());
    let mut logs: Vec<Log> = (0..12)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs.insert(0, flash_log);

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(stx.score >= 0.8);
    assert_eq!(stx.priority, AlertPriority::Critical);
}

#[test]
fn test_prefilter_default_construction() {
    let filter = PreFilter::default();
    // Verify it doesn't panic and basic properties hold
    let header = make_header(0);
    let result = filter.scan_block(&[], &[], &header);
    assert!(result.is_empty());
}

// ===========================================================================
// H-2: Deep Analysis Types Tests
// ===========================================================================

#[test]
fn test_analysis_config_defaults() {
    let config = AnalysisConfig::default();
    assert_eq!(config.max_steps, 1_000_000);
    assert!((config.min_alert_confidence - 0.4).abs() < f64::EPSILON);
}

#[test]
fn test_analysis_config_custom() {
    let config = AnalysisConfig {
        max_steps: 500_000,
        min_alert_confidence: 0.7,
        prefilter_alert_mode: true,
    };
    assert_eq!(config.max_steps, 500_000);
    assert!((config.min_alert_confidence - 0.7).abs() < f64::EPSILON);
    assert!(config.prefilter_alert_mode);
}

#[test]
fn test_sentinel_error_display() {
    let err = SentinelError::BlockNotFound {
        block_number: 19_500_000,
    };
    assert!(err.to_string().contains("19500000"));
    assert!(err.to_string().contains("not found"));

    let err = SentinelError::TxNotFound {
        block_number: 100,
        tx_index: 42,
    };
    assert!(err.to_string().contains("42"));
    assert!(err.to_string().contains("100"));

    let err = SentinelError::ParentNotFound { block_number: 200 };
    assert!(err.to_string().contains("200"));

    let err = SentinelError::StateRootMissing { block_number: 300 };
    assert!(err.to_string().contains("300"));

    let err = SentinelError::SenderRecovery {
        tx_index: 5,
        cause: "invalid signature".to_string(),
    };
    assert!(err.to_string().contains("5"));
    assert!(err.to_string().contains("invalid signature"));

    let err = SentinelError::StepLimitExceeded {
        steps: 2_000_000,
        max_steps: 1_000_000,
    };
    assert!(err.to_string().contains("2000000"));
    assert!(err.to_string().contains("1000000"));
}

#[test]
fn test_sentinel_error_vm() {
    let err = SentinelError::Vm("out of gas".to_string());
    assert!(err.to_string().contains("out of gas"));
}

#[test]
fn test_sentinel_error_db() {
    let err = SentinelError::Db("connection refused".to_string());
    assert!(err.to_string().contains("connection refused"));
}

#[test]
fn test_sentinel_alert_serialization() {
    let alert = SentinelAlert {
        block_number: 19_500_000,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 42,
        alert_priority: AlertPriority::Critical,
        suspicion_reasons: vec![SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        }],
        suspicion_score: 0.9,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::from(50_u64) * one_eth(),
        summary: "Flash Loan detected".to_string(),
        total_steps: 10_000,
        feature_vector: None,
    };

    let json = serde_json::to_string(&alert).expect("should serialize");
    assert!(json.contains("19500000"));
    assert!(json.contains("Flash Loan detected"));
    assert!(json.contains("Critical"));
    assert!(json.contains("10000"));
}

#[test]
fn test_sentinel_alert_priority_from_score() {
    // Critical threshold
    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: AlertPriority::from_score(0.85),
        suspicion_reasons: vec![],
        suspicion_score: 0.85,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        summary: String::new(),
        total_steps: 0,
        feature_vector: None,
    };
    assert_eq!(alert.alert_priority, AlertPriority::Critical);

    // High threshold
    let priority = AlertPriority::from_score(0.6);
    assert_eq!(priority, AlertPriority::High);
}

#[test]
fn test_sentinel_alert_empty_patterns() {
    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: AlertPriority::Medium,
        suspicion_reasons: vec![SuspicionReason::UnusualGasPattern {
            gas_used: 600_000,
            gas_limit: 620_000,
        }],
        suspicion_score: 0.15,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        summary: "Unusual gas pattern".to_string(),
        total_steps: 500,
        feature_vector: None,
    };

    assert_eq!(alert.tx_index, 0);
    assert_eq!(alert.total_steps, 500);
    assert_eq!(alert.suspicion_reasons.len(), 1);
}

#[test]
fn test_sentinel_alert_multiple_suspicion_reasons() {
    let reasons = vec![
        SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        },
        SuspicionReason::MultipleErc20Transfers { count: 15 },
        SuspicionReason::KnownContractInteraction {
            address: Address::zero(),
            label: "Aave V2 Pool".to_string(),
        },
    ];

    let total_score: f64 = reasons.iter().map(|r| r.score()).sum();
    // 0.4 + 0.4 (>10) + 0.1 = 0.9
    assert!((total_score - 0.9).abs() < f64::EPSILON);

    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 3,
        alert_priority: AlertPriority::from_score(total_score),
        suspicion_reasons: reasons,
        suspicion_score: total_score,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: one_eth(),
        summary: "Multi-signal alert".to_string(),
        total_steps: 8000,
        feature_vector: None,
    };

    assert_eq!(alert.alert_priority, AlertPriority::Critical);
    assert_eq!(alert.suspicion_reasons.len(), 3);
}

// ===========================================================================
// H-2: Replay module type tests
// ===========================================================================

#[test]
fn test_replay_result_fields() {
    // Test that ReplayResult struct has correct fields by constructing one
    use crate::sentinel::replay::ReplayResult;
    use crate::types::ReplayTrace;

    let result = ReplayResult {
        trace: ReplayTrace {
            steps: vec![],
            config: crate::types::ReplayConfig::default(),
            gas_used: 21000,
            success: true,
            output: bytes::Bytes::new(),
        },
        tx_sender: Address::zero(),
        block_header: make_header(100),
    };

    assert!(result.trace.steps.is_empty());
    assert_eq!(result.trace.gas_used, 21000);
    assert!(result.trace.success);
    assert_eq!(result.tx_sender, Address::zero());
    assert_eq!(result.block_header.number, 100);
}

// ===========================================================================
// H-2: Analyzer integration tests (with Store)
// ===========================================================================

// These tests require a populated Store. Since creating a full Store with
// committed blocks is complex (requires genesis + block execution), we test
// the analyzer at the type level and verify error paths.

#[test]
fn test_deep_analyzer_tx_not_found() {
    use crate::sentinel::analyzer::DeepAnalyzer;

    // Create a minimal Store (in-memory)
    let store = ethrex_storage::Store::new(
        "test-sentinel-analyzer",
        ethrex_storage::EngineType::InMemory,
    )
    .expect("in-memory store");

    // Block with 0 transactions
    let block = ethrex_common::types::Block {
        header: make_header(1),
        body: Default::default(),
    };

    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0, // no TX at index 0
        reasons: vec![SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        }],
        score: 0.5,
        priority: AlertPriority::High,
    };

    let config = AnalysisConfig::default();
    let result = DeepAnalyzer::analyze(&store, &block, &suspicion, &config, None);

    // Should fail because tx_index 0 doesn't exist in empty block
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, SentinelError::TxNotFound { .. }),
        "Expected TxNotFound, got: {err:?}"
    );
}

#[test]
fn test_deep_analyzer_parent_not_found() {
    use crate::sentinel::analyzer::DeepAnalyzer;

    let store =
        ethrex_storage::Store::new("test-sentinel-parent", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");

    // Block with 1 transaction but parent doesn't exist in Store
    let tx = make_tx_call(random_address(0x01), U256::zero(), 100_000);
    let block = ethrex_common::types::Block {
        header: BlockHeader {
            number: 100,
            parent_hash: H256::from([0xAA; 32]), // non-existent parent
            ..Default::default()
        },
        body: ethrex_common::types::BlockBody {
            transactions: vec![tx],
            ..Default::default()
        },
    };

    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![SuspicionReason::HighValueWithRevert {
            value_wei: one_eth(),
            gas_used: 200_000,
        }],
        score: 0.5,
        priority: AlertPriority::High,
    };

    let config = AnalysisConfig::default();
    let result = DeepAnalyzer::analyze(&store, &block, &suspicion, &config, None);

    // Should fail because parent block header is not in Store
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, SentinelError::ParentNotFound { .. }),
        "Expected ParentNotFound, got: {err:?}"
    );
}

#[test]
fn test_deep_analyzer_step_limit() {
    // Test that AnalysisConfig::max_steps is respected in SentinelError
    let err = SentinelError::StepLimitExceeded {
        steps: 2_000_000,
        max_steps: 1_000_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("2000000"));
    assert!(msg.contains("1000000"));
}

#[test]
fn test_load_block_header_not_found() {
    use crate::sentinel::replay::load_block_header;

    let store =
        ethrex_storage::Store::new("test-sentinel-load", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");

    let result = load_block_header(&store, 999_999);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), SentinelError::BlockNotFound { block_number } if block_number == 999_999)
    );
}

// ===========================================================================
// H-2: Autopsy-gated deep analysis tests
// ===========================================================================

#[cfg(feature = "autopsy")]
mod autopsy_sentinel_tests {
    use super::*;
    use crate::autopsy::types::{AttackPattern, DetectedPattern, FundFlow};

    #[test]
    fn test_sentinel_alert_with_detected_patterns() {
        let alert = SentinelAlert {
            block_number: 19_500_000,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 5,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![SuspicionReason::FlashLoanSignature {
                provider_address: Address::zero(),
            }],
            suspicion_score: 0.9,
            detected_patterns: vec![DetectedPattern {
                pattern: AttackPattern::FlashLoan {
                    borrow_step: 100,
                    borrow_amount: one_eth() * 1000,
                    repay_step: 5000,
                    repay_amount: one_eth() * 1001,
                    provider: Some(Address::zero()),
                    token: None,
                },
                confidence: 0.9,
                evidence: vec!["Borrow at step 100".to_string()],
            }],
            fund_flows: vec![FundFlow {
                from: random_address(0x01),
                to: random_address(0x02),
                value: one_eth() * 50,
                token: None,
                step_index: 200,
            }],
            total_value_at_risk: one_eth() * 50,
            summary: "Flash Loan detected".to_string(),
            total_steps: 10_000,
            feature_vector: None,
        };

        assert!((alert.max_confidence() - 0.9).abs() < f64::EPSILON);
        assert_eq!(alert.pattern_names(), vec!["FlashLoan"]);
    }

    #[test]
    fn test_sentinel_alert_max_confidence_multiple() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![],
            suspicion_score: 0.9,
            detected_patterns: vec![
                DetectedPattern {
                    pattern: AttackPattern::Reentrancy {
                        target_contract: Address::zero(),
                        reentrant_call_step: 50,
                        state_modified_step: 80,
                        call_depth_at_entry: 1,
                    },
                    confidence: 0.7,
                    evidence: vec!["Re-entry detected".to_string()],
                },
                DetectedPattern {
                    pattern: AttackPattern::FlashLoan {
                        borrow_step: 10,
                        borrow_amount: one_eth(),
                        repay_step: 500,
                        repay_amount: one_eth(),
                        provider: None,
                        token: None,
                    },
                    confidence: 0.85,
                    evidence: vec!["Flash loan pattern".to_string()],
                },
            ],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: String::new(),
            total_steps: 1000,
            feature_vector: None,
        };

        // max_confidence should return the highest
        assert!((alert.max_confidence() - 0.85).abs() < f64::EPSILON);
        let names = alert.pattern_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Reentrancy"));
        assert!(names.contains(&"FlashLoan"));
    }

    #[test]
    fn test_sentinel_alert_empty_patterns_confidence() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Medium,
            suspicion_reasons: vec![],
            suspicion_score: 0.3,
            detected_patterns: vec![],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: String::new(),
            total_steps: 0,
            feature_vector: None,
        };

        assert!((alert.max_confidence() - 0.0).abs() < f64::EPSILON);
        assert!(alert.pattern_names().is_empty());
    }

    #[test]
    fn test_sentinel_alert_serialization_with_autopsy() {
        let alert = SentinelAlert {
            block_number: 19_500_000,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 42,
            alert_priority: AlertPriority::High,
            suspicion_reasons: vec![SuspicionReason::PriceOracleWithSwap {
                oracle: Address::zero(),
            }],
            suspicion_score: 0.6,
            detected_patterns: vec![DetectedPattern {
                pattern: AttackPattern::PriceManipulation {
                    oracle_read_before: 100,
                    swap_step: 200,
                    oracle_read_after: 300,
                    price_delta_percent: 15.5,
                },
                confidence: 0.8,
                evidence: vec!["Price delta 15.5%".to_string()],
            }],
            fund_flows: vec![],
            total_value_at_risk: one_eth() * 100,
            summary: "Price manipulation detected".to_string(),
            total_steps: 5000,
            feature_vector: None,
        };

        let json = serde_json::to_string_pretty(&alert).expect("should serialize");
        assert!(json.contains("PriceManipulation"));
        assert!(json.contains("15.5"));
        assert!(json.contains("Price manipulation detected"));
    }

    #[test]
    fn test_sentinel_alert_all_pattern_names() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![],
            suspicion_score: 1.0,
            detected_patterns: vec![
                DetectedPattern {
                    pattern: AttackPattern::Reentrancy {
                        target_contract: Address::zero(),
                        reentrant_call_step: 1,
                        state_modified_step: 2,
                        call_depth_at_entry: 1,
                    },
                    confidence: 0.9,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::FlashLoan {
                        borrow_step: 1,
                        borrow_amount: U256::zero(),
                        repay_step: 2,
                        repay_amount: U256::zero(),
                        provider: None,
                        token: None,
                    },
                    confidence: 0.8,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::PriceManipulation {
                        oracle_read_before: 1,
                        swap_step: 2,
                        oracle_read_after: 3,
                        price_delta_percent: 10.0,
                    },
                    confidence: 0.7,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::AccessControlBypass {
                        sstore_step: 1,
                        contract: Address::zero(),
                    },
                    confidence: 0.5,
                    evidence: vec![],
                },
            ],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: String::new(),
            total_steps: 100,
            feature_vector: None,
        };

        let names = alert.pattern_names();
        assert_eq!(names.len(), 4);
        assert_eq!(names[0], "Reentrancy");
        assert_eq!(names[1], "FlashLoan");
        assert_eq!(names[2], "PriceManipulation");
        assert_eq!(names[3], "AccessControlBypass");
        assert!((alert.max_confidence() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sentinel_alert_fund_flow_value() {
        let flows = vec![
            FundFlow {
                from: random_address(0x01),
                to: random_address(0x02),
                value: one_eth() * 10,
                token: None, // ETH
                step_index: 100,
            },
            FundFlow {
                from: random_address(0x02),
                to: random_address(0x03),
                value: one_eth() * 5,
                token: None, // ETH
                step_index: 200,
            },
            FundFlow {
                from: random_address(0x01),
                to: random_address(0x04),
                value: one_eth() * 100,
                token: Some(random_address(0xDD)), // ERC-20, should be excluded
                step_index: 300,
            },
        ];

        // compute_total_value only counts ETH (token: None)
        let total: U256 = flows
            .iter()
            .filter(|f| f.token.is_none())
            .fold(U256::zero(), |acc, f| acc.saturating_add(f.value));

        assert_eq!(total, one_eth() * 15);
    }
}

// ---------------------------------------------------------------------------
// H-3: SentinelService + BlockObserver tests
// ---------------------------------------------------------------------------

mod service_tests {
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

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

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

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));
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

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

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

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

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
            summary: "Test alert".to_string(),
            total_steps: 100,
            feature_vector: None,
        };

        handler.on_alert(alert);
    }

    #[test]
    fn test_service_shutdown_idempotent() {
        let store = test_store();
        let config = SentinelConfig::default();
        let analysis_config = AnalysisConfig::default();

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

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

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(LogAlertHandler));

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
            summary: "Test".to_string(),
            total_steps: 0,
            feature_vector: None,
        };

        handler.on_alert(alert.clone());
        handler.on_alert(alert.clone());
        handler.on_alert(alert);

        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}

// ===========================================================================
// H-5: Integration tests — cross-module wiring
// ===========================================================================

mod h5_integration_tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ethrex_common::{H256, U256};

    use crate::sentinel::alert::{AlertDispatcher, JsonlFileAlertHandler};
    use crate::sentinel::history::{AlertHistory, AlertQueryParams, SortOrder};
    use crate::sentinel::metrics::SentinelMetrics;
    use crate::sentinel::service::AlertHandler;
    use crate::sentinel::types::{AlertPriority, SentinelAlert};
    use crate::sentinel::ws_broadcaster::{WsAlertBroadcaster, WsAlertHandler};

    /// Atomic counter for unique temp file paths across tests.
    static H5_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_jsonl_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sentinel_h5_integration");
        let _ = std::fs::create_dir_all(&dir);
        let id = H5_FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
        dir.join(format!("h5_{}_{}.jsonl", std::process::id(), id))
    }

    fn make_alert(block_number: u64, priority: AlertPriority, tx_hash_byte: u8) -> SentinelAlert {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = tx_hash_byte;
        SentinelAlert {
            block_number,
            block_hash: H256::zero(),
            tx_hash: H256::from(hash_bytes),
            tx_index: 0,
            alert_priority: priority,
            suspicion_reasons: vec![],
            suspicion_score: match priority {
                AlertPriority::Critical => 0.9,
                AlertPriority::High => 0.6,
                AlertPriority::Medium => 0.4,
            },
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: format!("H5 test alert block={}", block_number),
            total_steps: 100,
            feature_vector: None,
        }
    }

    /// H-5 Test 1: AlertDispatcher with WsAlertHandler — write via pipeline,
    /// verify WebSocket subscriber receives the alert.
    #[test]
    fn test_h5_ws_broadcaster_with_alert_dispatcher() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let rx = broadcaster.subscribe();

        let ws_handler = WsAlertHandler::new(broadcaster.clone());
        let dispatcher = AlertDispatcher::new(vec![Box::new(ws_handler)]);

        let alert = make_alert(500, AlertPriority::High, 0xAA);
        dispatcher.on_alert(alert);

        let msg = rx.recv().expect("subscriber should receive alert");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 500);
        assert_eq!(parsed["alert_priority"], "High");
    }

    /// H-5 Test 2: Write alerts via JsonlFileAlertHandler, then read back
    /// via AlertHistory.query() — full roundtrip.
    #[test]
    fn test_h5_history_roundtrip_with_jsonl() {
        let path = unique_jsonl_path();

        // Write phase: push 3 alerts through the JSONL handler
        let handler = JsonlFileAlertHandler::new(path.clone());
        handler.on_alert(make_alert(100, AlertPriority::Medium, 0x01));
        handler.on_alert(make_alert(101, AlertPriority::High, 0x02));
        handler.on_alert(make_alert(102, AlertPriority::Critical, 0x03));

        // Read phase: query back via AlertHistory
        let history = AlertHistory::new(path.clone());
        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 3);
        assert_eq!(result.alerts.len(), 3);

        // Newest first (default sort)
        assert_eq!(result.alerts[0].block_number, 102);
        assert_eq!(result.alerts[1].block_number, 101);
        assert_eq!(result.alerts[2].block_number, 100);

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 3: Pagination consistency — 25 alerts, pages of 10, no duplicates.
    #[test]
    fn test_h5_history_pagination_consistency() {
        let path = unique_jsonl_path();

        let handler = JsonlFileAlertHandler::new(path.clone());
        for i in 0..25 {
            handler.on_alert(make_alert(200 + i, AlertPriority::High, i as u8));
        }

        let history = AlertHistory::new(path.clone());

        let p1 = history.query(&AlertQueryParams {
            page: 1,
            page_size: 10,
            ..Default::default()
        });
        let p2 = history.query(&AlertQueryParams {
            page: 2,
            page_size: 10,
            ..Default::default()
        });
        let p3 = history.query(&AlertQueryParams {
            page: 3,
            page_size: 10,
            ..Default::default()
        });

        // All pages report the same total
        assert_eq!(p1.total_count, 25);
        assert_eq!(p2.total_count, 25);
        assert_eq!(p3.total_count, 25);

        // Page sizes
        assert_eq!(p1.alerts.len(), 10);
        assert_eq!(p2.alerts.len(), 10);
        assert_eq!(p3.alerts.len(), 5);

        // Total pages
        assert_eq!(p1.total_pages, 3);

        // No duplicates across pages
        let mut all_blocks: Vec<u64> = Vec::new();
        all_blocks.extend(p1.alerts.iter().map(|a| a.block_number));
        all_blocks.extend(p2.alerts.iter().map(|a| a.block_number));
        all_blocks.extend(p3.alerts.iter().map(|a| a.block_number));

        let unique: HashSet<u64> = all_blocks.iter().copied().collect();
        assert_eq!(unique.len(), 25, "all 25 alerts should appear exactly once");

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 4: Metrics counters increment correctly under direct usage.
    #[test]
    fn test_h5_metrics_increment_during_processing() {
        let metrics = SentinelMetrics::new();

        // Simulate a processing cycle
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(50);
        metrics.increment_txs_flagged(3);
        metrics.increment_alerts_emitted();
        metrics.increment_alerts_emitted();
        metrics.add_prefilter_us(1200);
        metrics.add_deep_analysis_ms(45);

        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_scanned, 1);
        assert_eq!(snap.txs_scanned, 50);
        assert_eq!(snap.txs_flagged, 3);
        assert_eq!(snap.alerts_emitted, 2);
        assert_eq!(snap.prefilter_total_us, 1200);
        assert_eq!(snap.deep_analysis_total_ms, 45);

        // Simulate second block
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(30);

        let snap2 = metrics.snapshot();
        assert_eq!(snap2.blocks_scanned, 2);
        assert_eq!(snap2.txs_scanned, 80);
        // Previous snapshot is frozen
        assert_eq!(snap.blocks_scanned, 1);
    }

    /// H-5 Test 5: 10 concurrent subscribers all receive the same broadcast.
    #[test]
    fn test_h5_ws_concurrent_subscribers() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());

        let receivers: Vec<_> = (0..10).map(|_| broadcaster.subscribe()).collect();

        let alert = make_alert(999, AlertPriority::Critical, 0xFF);
        broadcaster.broadcast(&alert);

        for (i, rx) in receivers.iter().enumerate() {
            let msg = rx
                .recv()
                .unwrap_or_else(|_| panic!("subscriber {} should receive", i));
            let parsed: serde_json::Value = serde_json::from_str(&msg).expect("valid JSON");
            assert_eq!(parsed["block_number"], 999);
            assert_eq!(parsed["alert_priority"], "Critical");
        }
    }

    /// H-5 Test 6: 500 alerts with varying blocks, query with block_range filter.
    #[test]
    fn test_h5_history_large_file() {
        let path = unique_jsonl_path();

        let handler = JsonlFileAlertHandler::new(path.clone());
        for i in 0u64..500 {
            let priority = match i % 3 {
                0 => AlertPriority::Medium,
                1 => AlertPriority::High,
                _ => AlertPriority::Critical,
            };
            handler.on_alert(make_alert(1000 + i, priority, (i % 256) as u8));
        }

        let history = AlertHistory::new(path.clone());

        // Query a narrow range: blocks 1200..1250 (inclusive) = 51 alerts
        let result = history.query(&AlertQueryParams {
            block_range: Some((1200, 1250)),
            page_size: 100,
            ..Default::default()
        });

        assert_eq!(result.total_count, 51);
        for alert in &result.alerts {
            assert!(
                alert.block_number >= 1200 && alert.block_number <= 1250,
                "block {} out of range",
                alert.block_number
            );
        }

        // Verify sort order (newest first by default)
        for window in result.alerts.windows(2) {
            assert!(
                window[0].block_number >= window[1].block_number,
                "should be sorted descending"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 7: Prometheus text output contains expected metric lines.
    #[test]
    fn test_h5_metrics_prometheus_format_valid() {
        let metrics = SentinelMetrics::new();

        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(100);
        metrics.increment_txs_flagged(7);
        metrics.increment_alerts_emitted();
        metrics.increment_alerts_deduplicated();
        metrics.increment_alerts_rate_limited();
        metrics.add_prefilter_us(5000);
        metrics.add_deep_analysis_ms(250);

        let text = metrics.to_prometheus_text();

        // Verify expected values appear
        assert!(text.contains("sentinel_blocks_scanned 3"));
        assert!(text.contains("sentinel_txs_scanned 100"));
        assert!(text.contains("sentinel_txs_flagged 7"));
        assert!(text.contains("sentinel_alerts_emitted 1"));
        assert!(text.contains("sentinel_alerts_deduplicated 1"));
        assert!(text.contains("sentinel_alerts_rate_limited 1"));
        assert!(text.contains("sentinel_prefilter_total_us 5000"));
        assert!(text.contains("sentinel_deep_analysis_total_ms 250"));

        // Verify Prometheus format structure (HELP + TYPE per metric)
        let help_count = text.matches("# HELP").count();
        let type_count = text.matches("# TYPE").count();
        assert_eq!(help_count, 14, "should have 14 HELP lines");
        assert_eq!(type_count, 14, "should have 14 TYPE lines");

        // All types should be counters
        assert_eq!(
            text.matches("# TYPE").count(),
            text.matches("counter").count(),
            "all metrics should be counters"
        );
    }

    /// H-5 Test 8: Full pipeline wiring — AlertDispatcher with WsAlertHandler
    /// + JsonlFileAlertHandler, then verify both outputs work.
    #[test]
    fn test_h5_full_pipeline_with_all_handlers() {
        let path = unique_jsonl_path();

        // Set up WebSocket broadcaster
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let rx = broadcaster.subscribe();
        let ws_handler = WsAlertHandler::new(broadcaster);

        // Set up JSONL file handler
        let jsonl_handler = JsonlFileAlertHandler::new(path.clone());

        // Wire into dispatcher
        let dispatcher = AlertDispatcher::new(vec![Box::new(ws_handler), Box::new(jsonl_handler)]);

        // Emit 3 alerts through the pipeline
        dispatcher.on_alert(make_alert(300, AlertPriority::Medium, 0x01));
        dispatcher.on_alert(make_alert(301, AlertPriority::High, 0x02));
        dispatcher.on_alert(make_alert(302, AlertPriority::Critical, 0x03));

        // Verify WebSocket subscriber received all 3
        let ws_msg1: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let ws_msg2: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let ws_msg3: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();

        assert_eq!(ws_msg1["block_number"], 300);
        assert_eq!(ws_msg2["block_number"], 301);
        assert_eq!(ws_msg3["block_number"], 302);

        // Verify JSONL file contains all 3, readable via AlertHistory
        let history = AlertHistory::new(path.clone());
        let result = history.query(&AlertQueryParams {
            sort_order: SortOrder::Oldest,
            ..Default::default()
        });

        assert_eq!(result.total_count, 3);
        assert_eq!(result.alerts[0].block_number, 300);
        assert_eq!(result.alerts[1].block_number, 301);
        assert_eq!(result.alerts[2].block_number, 302);

        let _ = std::fs::remove_file(&path);
    }
}

// ===========================================================================
// Reentrancy E2E Demo — Proves the full attack detection pipeline works
// end-to-end with actual reentrancy contract bytecodes.
// ===========================================================================

/// Test 1: Bytecode-level reentrancy detection via AttackClassifier.
///
/// Executes actual attacker + victim contracts through LEVM, captures the
/// opcode trace, and verifies the classifier detects Reentrancy with
/// confidence >= 0.7.
#[cfg(feature = "autopsy")]
mod reentrancy_bytecode_tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use ethrex_common::constants::EMPTY_TRIE_HASH;
    use ethrex_common::types::{
        Account, BlockHeader, Code, EIP1559Transaction, Transaction, TxKind,
    };
    use ethrex_common::{Address, U256};
    use ethrex_levm::Environment;
    use ethrex_levm::db::gen_db::GeneralizedDatabase;
    use rustc_hash::FxHashMap;

    use crate::autopsy::classifier::AttackClassifier;
    use crate::autopsy::types::AttackPattern;
    use crate::engine::ReplayEngine;
    use crate::types::ReplayConfig;

    /// Gas limit — large enough for reentrancy but not overflowing.
    const TEST_GAS_LIMIT: u64 = 10_000_000;

    /// Large balance that won't overflow on small additions (unlike U256::MAX).
    fn big_balance() -> U256 {
        U256::from(10).pow(U256::from(30))
    }

    fn make_test_db(accounts: Vec<(Address, Code)>) -> GeneralizedDatabase {
        let store = ethrex_storage::Store::new("", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");
        let header = BlockHeader {
            state_root: *EMPTY_TRIE_HASH,
            ..Default::default()
        };
        let vm_db: ethrex_vm::DynVmDatabase = Box::new(
            ethrex_blockchain::vm::StoreVmDatabase::new(store, header).expect("StoreVmDatabase"),
        );

        let balance = big_balance();
        let mut cache = FxHashMap::default();
        for (addr, code) in accounts {
            cache.insert(addr, Account::new(balance, code, 0, FxHashMap::default()));
        }

        GeneralizedDatabase::new_with_account_state(Arc::new(vm_db), cache)
    }

    /// Victim Contract (20 bytes):
    /// Sends 1 wei to CALLER via CALL, then SSTORE slot 0 = 1.
    /// Vulnerable: state update AFTER external call.
    ///
    /// Bytecode:
    ///   PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 1  CALLER  PUSH2 0xFFFF  CALL
    ///   POP  PUSH1 1  PUSH1 0  SSTORE  STOP
    fn victim_bytecode() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0 (retLen)
            0x60, 0x00, // PUSH1 0 (retOff)
            0x60, 0x00, // PUSH1 0 (argsLen)
            0x60, 0x00, // PUSH1 0 (argsOff)
            0x60, 0x01, // PUSH1 1 (value = 1 wei)
            0x33, // CALLER
            0x61, 0xFF, 0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP (return status)
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE(slot=0, value=1)
            0x00, // STOP
        ]
    }

    /// Attacker Contract (38 bytes):
    /// Counter in slot 0. If counter < 2: increment + CALL victim.
    /// If counter >= 2: STOP.
    ///
    /// Bytecode:
    ///   SLOAD(0)  DUP1  PUSH1 2  GT  ISZERO  PUSH1 0x23  JUMPI
    ///   PUSH1 1  ADD  PUSH1 0  SSTORE
    ///   PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0
    ///   PUSH1 <victim_lo>  PUSH2 0xFFFF  CALL  POP  STOP
    ///   JUMPDEST  POP  STOP
    fn attacker_bytecode(victim_addr: Address) -> Vec<u8> {
        // Extract low byte of victim address for PUSH1
        let victim_byte = victim_addr.as_bytes()[19];
        // Bytecode layout (byte offsets):
        //  0: PUSH1 0       2: SLOAD      3: DUP1       4: PUSH1 2
        //  6: GT            7: ISZERO     8: PUSH1 0x23  10: JUMPI
        // 11: PUSH1 1      13: ADD       14: PUSH1 0    16: SSTORE
        // 17: PUSH1 0 (retLen)  19: PUSH1 0 (retOff)  21: PUSH1 0 (argsLen)
        // 23: PUSH1 0 (argsOff) 25: PUSH1 0 (value)   27: PUSH1 victim
        // 29: PUSH2 0xFFFF 32: CALL      33: POP       34: STOP
        // 35: JUMPDEST      36: POP       37: STOP
        vec![
            0x60,
            0x00, // 0: PUSH1 0 (slot)
            0x54, // 2: SLOAD(0) → counter
            0x80, // 3: DUP1
            0x60,
            0x02, // 4: PUSH1 2
            0x11, // 6: GT — stack: [2, counter] → 2 > counter
            0x15, // 7: ISZERO — !(2 > counter) = counter >= 2
            0x60,
            0x23, // 8: PUSH1 0x23 = 35 (JUMPDEST offset)
            0x57, // 10: JUMPI (jump if counter >= 2)
            // counter < 2 path: increment + CALL victim
            0x60,
            0x01, // 11: PUSH1 1
            0x01, // 13: ADD (counter + 1)
            0x60,
            0x00, // 14: PUSH1 0
            0x55, // 16: SSTORE(slot=0, value=counter+1)
            // CALL victim(gas=0xFFFF, addr=victim, value=0, args=0,0, ret=0,0)
            0x60,
            0x00, // 17: PUSH1 0 (retLen)
            0x60,
            0x00, // 19: PUSH1 0 (retOff)
            0x60,
            0x00, // 21: PUSH1 0 (argsLen)
            0x60,
            0x00, // 23: PUSH1 0 (argsOff)
            0x60,
            0x00, // 25: PUSH1 0 (value)
            0x60,
            victim_byte, // 27: PUSH1 victim_addr
            0x61,
            0xFF,
            0xFF, // 29: PUSH2 0xFFFF (gas)
            0xF1, // 32: CALL
            0x50, // 33: POP
            0x00, // 34: STOP
            // counter >= 2 path
            0x5B, // 35: JUMPDEST
            0x50, // 36: POP (discard duplicated counter)
            0x00, // 37: STOP
        ]
    }

    #[test]
    fn reentrancy_bytecode_classifier_detects_attack() {
        let attacker_addr = Address::from_low_u64_be(0x42);
        let victim_addr = Address::from_low_u64_be(0x43);
        let sender_addr = Address::from_low_u64_be(0x100);

        let accounts = vec![
            (
                attacker_addr,
                Code::from_bytecode(Bytes::from(attacker_bytecode(victim_addr))),
            ),
            (
                victim_addr,
                Code::from_bytecode(Bytes::from(victim_bytecode())),
            ),
            (sender_addr, Code::from_bytecode(Bytes::new())),
        ];

        let mut db = make_test_db(accounts);
        let env = Environment {
            origin: sender_addr,
            gas_limit: TEST_GAS_LIMIT,
            block_gas_limit: TEST_GAS_LIMIT,
            ..Default::default()
        };
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(attacker_addr),
            data: Bytes::new(),
            ..Default::default()
        });

        let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())
            .expect("reentrancy TX should execute successfully");

        let steps = engine.steps_range(0, engine.len());

        // Verify trace has sufficient depth (attacker → victim → attacker re-entry)
        let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);
        assert!(
            max_depth >= 3,
            "Expected call depth >= 3 for reentrancy, got {max_depth}"
        );

        // Run the classifier
        let detected = AttackClassifier::classify_with_confidence(&steps);

        // Should find at least one Reentrancy pattern
        let reentrancy = detected
            .iter()
            .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));

        assert!(
            reentrancy.is_some(),
            "Classifier should detect reentrancy. Detected patterns: {detected:?}"
        );

        let reentrancy = reentrancy.unwrap();
        assert!(
            reentrancy.confidence >= 0.7,
            "Reentrancy confidence should be >= 0.7, got {}",
            reentrancy.confidence
        );

        // The classifier identifies re-entry by finding a contract that is called,
        // then called again before the first call completes. In our setup:
        //   sender → attacker → victim → attacker (re-entry!)
        // So the attacker is the contract being re-entered.
        if let AttackPattern::Reentrancy {
            target_contract, ..
        } = &reentrancy.pattern
        {
            assert_eq!(
                *target_contract, attacker_addr,
                "Reentrancy target should be the re-entered contract (attacker)"
            );
        }
    }
}

/// Test 2: PreFilter flags a suspicious receipt matching reentrancy-like patterns.
mod reentrancy_prefilter_tests {
    use ethrex_common::types::{LegacyTransaction, Transaction, TxKind};
    use ethrex_common::{Address, U256};

    use super::*;

    #[test]
    fn reentrancy_prefilter_flags_suspicious_receipt() {
        let filter = PreFilter::default(); // threshold = 0.5

        // Construct a reverted TX with 5 ETH value + 2M gas + no logs.
        // H2 (high value revert): 5 ETH > 1 ETH threshold, reverted, gas=2M > 100k → score 0.3
        // H6 (self-destruct indicators): reverted, gas > 1M, empty logs → score 0.3
        // Total: 0.6 >= 0.5 threshold → flagged
        let five_eth = U256::from(5_000_000_000_000_000_000_u64);
        let receipt = make_receipt(false, 2_000_000, vec![]);
        let tx = Transaction::LegacyTransaction(LegacyTransaction {
            gas: 3_000_000,
            to: TxKind::Call(Address::from_low_u64_be(0xDEAD)),
            value: five_eth,
            data: Bytes::new(),
            ..Default::default()
        });
        let header = make_header(19_500_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_some(),
            "PreFilter should flag high-value reverted TX"
        );

        let stx = result.unwrap();
        assert!(
            stx.score >= 0.5,
            "Score should be >= 0.5, got {}",
            stx.score
        );

        // Verify both H2 and H6 reasons are present
        let has_high_value_revert = stx
            .reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::HighValueWithRevert { .. }));
        let has_self_destruct = stx
            .reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::SelfDestructDetected));
        assert!(
            has_high_value_revert,
            "Should have HighValueWithRevert reason"
        );
        assert!(has_self_destruct, "Should have SelfDestructDetected reason");
    }
}

/// Test 3: Full E2E SentinelService with prefilter_alert_mode.
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

// ===========================================================================
// Live Reentrancy Pipeline — Full 6-phase E2E test with real bytecode execution.
//
// Unlike the mock-receipt tests above, this test:
//   1. Deploys actual attacker + victim contracts in LEVM
//   2. Executes the reentrancy attack and captures the opcode trace
//   3. Runs AttackClassifier + FundFlowTracer on the real trace
//   4. Feeds real execution results through the SentinelService pipeline
//   5. Verifies alerts and metrics end-to-end
// ===========================================================================

#[cfg(feature = "autopsy")]
mod live_reentrancy_pipeline_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use bytes::Bytes;
    use ethrex_common::constants::EMPTY_TRIE_HASH;
    use ethrex_common::types::{
        Account, Block, BlockBody, BlockHeader, Code, EIP1559Transaction, Receipt, Transaction,
        TxKind, TxType,
    };
    use ethrex_common::{Address, U256};
    use ethrex_levm::db::gen_db::GeneralizedDatabase;
    use ethrex_levm::Environment;
    use ethrex_storage::{EngineType, Store};
    use rustc_hash::FxHashMap;

    use crate::autopsy::classifier::AttackClassifier;
    use crate::autopsy::fund_flow::FundFlowTracer;
    use crate::autopsy::types::AttackPattern;
    use crate::engine::ReplayEngine;
    use crate::sentinel::service::{AlertHandler, SentinelService};
    use crate::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelConfig};
    use crate::types::ReplayConfig;

    const TEST_GAS_LIMIT: u64 = 10_000_000;

    fn big_balance() -> U256 {
        U256::from(10).pow(U256::from(30))
    }

    fn make_test_db(accounts: Vec<(Address, Code)>) -> GeneralizedDatabase {
        let store =
            Store::new("", EngineType::InMemory).expect("in-memory store");
        let header = BlockHeader {
            state_root: *EMPTY_TRIE_HASH,
            ..Default::default()
        };
        let vm_db: ethrex_vm::DynVmDatabase = Box::new(
            ethrex_blockchain::vm::StoreVmDatabase::new(store, header)
                .expect("StoreVmDatabase"),
        );

        let balance = big_balance();
        let mut cache = FxHashMap::default();
        for (addr, code) in accounts {
            cache.insert(addr, Account::new(balance, code, 0, FxHashMap::default()));
        }

        GeneralizedDatabase::new_with_account_state(Arc::new(vm_db), cache)
    }

    /// Victim: sends 1 wei to CALLER via CALL, then SSTORE slot 0 = 1.
    fn victim_bytecode() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0 (retLen)
            0x60, 0x00, // PUSH1 0 (retOff)
            0x60, 0x00, // PUSH1 0 (argsLen)
            0x60, 0x00, // PUSH1 0 (argsOff)
            0x60, 0x01, // PUSH1 1 (value = 1 wei)
            0x33, // CALLER
            0x61, 0xFF, 0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE(slot=0, value=1)
            0x00, // STOP
        ]
    }

    /// Attacker: counter in slot 0. If counter < 2: increment + CALL victim.
    fn attacker_bytecode(victim_addr: Address) -> Vec<u8> {
        let victim_byte = victim_addr.as_bytes()[19];
        vec![
            0x60, 0x00, // PUSH1 0 (slot)
            0x54, // SLOAD(0)
            0x80, // DUP1
            0x60, 0x02, // PUSH1 2
            0x11, // GT
            0x15, // ISZERO
            0x60, 0x23, // PUSH1 0x23
            0x57, // JUMPI
            0x60, 0x01, // PUSH1 1
            0x01, // ADD
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE
            0x60, 0x00, // PUSH1 0 (retLen)
            0x60, 0x00, // PUSH1 0 (retOff)
            0x60, 0x00, // PUSH1 0 (argsLen)
            0x60, 0x00, // PUSH1 0 (argsOff)
            0x60, 0x00, // PUSH1 0 (value)
            0x60, victim_byte, // PUSH1 victim
            0x61, 0xFF, 0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP
            0x00, // STOP
            0x5B, // JUMPDEST
            0x50, // POP
            0x00, // STOP
        ]
    }

    struct CapturingAlertHandler {
        count: Arc<AtomicUsize>,
        alerts: Arc<std::sync::Mutex<Vec<SentinelAlert>>>,
    }

    impl AlertHandler for CapturingAlertHandler {
        fn on_alert(&self, alert: SentinelAlert) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut v) = self.alerts.lock() {
                v.push(alert);
            }
        }
    }

    #[test]
    fn test_live_reentrancy_full_detection_pipeline() {
        // ---------------------------------------------------------------
        // Phase 1: Deploy & Execute — real reentrancy attack in LEVM
        // ---------------------------------------------------------------
        let attacker_addr = Address::from_low_u64_be(0x42);
        let victim_addr = Address::from_low_u64_be(0x43);
        let sender_addr = Address::from_low_u64_be(0x100);

        let accounts = vec![
            (
                attacker_addr,
                Code::from_bytecode(Bytes::from(attacker_bytecode(victim_addr))),
            ),
            (
                victim_addr,
                Code::from_bytecode(Bytes::from(victim_bytecode())),
            ),
            (sender_addr, Code::from_bytecode(Bytes::new())),
        ];

        let mut db = make_test_db(accounts);
        let env = Environment {
            origin: sender_addr,
            gas_limit: TEST_GAS_LIMIT,
            block_gas_limit: TEST_GAS_LIMIT,
            ..Default::default()
        };
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(attacker_addr),
            data: Bytes::new(),
            ..Default::default()
        });

        let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())
            .expect("reentrancy TX should execute successfully");

        let trace = engine.trace();
        let steps = engine.steps_range(0, engine.len());

        // ---------------------------------------------------------------
        // Phase 2: Verify Attack — call depth >= 3, SSTORE exists
        // ---------------------------------------------------------------
        let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);
        assert!(
            max_depth >= 3,
            "Expected call depth >= 3 for reentrancy, got {max_depth}"
        );

        let sstore_count = steps.iter().filter(|s| s.opcode == 0x55).count();
        assert!(
            sstore_count >= 2,
            "Expected at least 2 SSTOREs (attacker counter writes), got {sstore_count}"
        );

        // ---------------------------------------------------------------
        // Phase 3: Classify — AttackClassifier detects Reentrancy
        // ---------------------------------------------------------------
        let detected = AttackClassifier::classify_with_confidence(steps);

        let reentrancy = detected
            .iter()
            .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));

        assert!(
            reentrancy.is_some(),
            "AttackClassifier should detect reentrancy on real trace. Detected: {detected:?}"
        );

        let reentrancy = reentrancy.unwrap();
        assert!(
            reentrancy.confidence >= 0.7,
            "Reentrancy confidence should be >= 0.7, got {}",
            reentrancy.confidence
        );

        if let AttackPattern::Reentrancy {
            target_contract, ..
        } = &reentrancy.pattern
        {
            assert_eq!(
                *target_contract, attacker_addr,
                "Reentrancy target should be the re-entered contract (attacker)"
            );
        }

        // ---------------------------------------------------------------
        // Phase 4: Fund Flow — ETH transfers from victim → attacker
        // ---------------------------------------------------------------
        let flows = FundFlowTracer::trace(steps);

        let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
        assert!(
            !eth_flows.is_empty(),
            "FundFlowTracer should detect ETH transfers (victim sends 1 wei per CALL)"
        );

        // Verify at least one flow goes from victim to attacker
        let victim_to_attacker = eth_flows
            .iter()
            .any(|f| f.from == victim_addr && f.to == attacker_addr);
        assert!(
            victim_to_attacker,
            "Should have ETH flow from victim ({victim_addr:?}) to attacker ({attacker_addr:?}). Flows: {eth_flows:?}"
        );

        // ---------------------------------------------------------------
        // Phase 5: Sentinel Pipeline — real receipt → SentinelService
        // ---------------------------------------------------------------
        let alert_count = Arc::new(AtomicUsize::new(0));
        let captured_alerts = Arc::new(std::sync::Mutex::new(Vec::<SentinelAlert>::new()));
        let handler = CapturingAlertHandler {
            count: alert_count.clone(),
            alerts: captured_alerts.clone(),
        };

        let store = Store::new("", EngineType::InMemory).expect("in-memory store");

        // Tuned config for stealthy reentrancy (1 wei value, ~82k gas):
        // - suspicion_threshold: 0.1 (production: 0.5, designed for loud attacks)
        // - min_gas_used: 50_000 (production: 500_000) — our attack uses ~82k gas
        // This demonstrates the pipeline works even for stealthy, low-gas attacks.
        let config = SentinelConfig {
            suspicion_threshold: 0.1,
            min_gas_used: 50_000,
            ..Default::default()
        };

        // prefilter_alert_mode: deep analysis can't replay from Store
        // (no genesis state) — emit lightweight alert from PreFilter.
        let analysis_config = AnalysisConfig {
            prefilter_alert_mode: true,
            ..Default::default()
        };

        let service =
            SentinelService::new(store, config, analysis_config, Box::new(handler));

        // Build receipt from real execution results
        let receipt = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: trace.success,
            cumulative_gas_used: trace.gas_used,
            logs: vec![],
        };

        // Set gas_limit close to gas_used (>95% ratio) to trigger H5 gas anomaly
        let tight_gas_limit = trace.gas_used + trace.gas_used / 20; // ~105% of used
        let sentinel_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(attacker_addr),
            gas_limit: tight_gas_limit,
            data: Bytes::new(),
            ..Default::default()
        });

        let block = Block {
            header: BlockHeader {
                number: 19_500_000,
                gas_used: trace.gas_used,
                gas_limit: 30_000_000,
                ..Default::default()
            },
            body: BlockBody {
                transactions: vec![sentinel_tx],
                ..Default::default()
            },
        };

        use ethrex_blockchain::BlockObserver;
        service.on_block_committed(block, vec![receipt]);

        // Wait for worker thread to process
        std::thread::sleep(std::time::Duration::from_millis(300));

        // ---------------------------------------------------------------
        // Phase 6: Alert Validation — verify alert content + metrics
        // ---------------------------------------------------------------
        let count = alert_count.load(Ordering::SeqCst);
        assert!(
            count >= 1,
            "Expected at least 1 alert from sentinel pipeline, got {count}"
        );

        // Verify alert has suspicion reasons
        let alerts = captured_alerts.lock().unwrap();
        let alert = &alerts[0];
        assert!(
            !alert.suspicion_reasons.is_empty(),
            "Alert should have at least one suspicion reason"
        );
        assert!(
            alert.suspicion_score > 0.0,
            "Alert suspicion_score should be > 0, got {}",
            alert.suspicion_score
        );

        // Verify metrics
        let snap = service.metrics().snapshot();
        assert!(
            snap.blocks_scanned >= 1,
            "Expected blocks_scanned >= 1, got {}",
            snap.blocks_scanned
        );
        assert!(
            snap.txs_scanned >= 1,
            "Expected txs_scanned >= 1, got {}",
            snap.txs_scanned
        );
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
