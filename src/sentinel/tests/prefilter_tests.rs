//! PreFilter heuristic tests: H1–H7, config, threshold, integration.

use super::*;

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
    assert_eq!(AlertPriority::from_score(0.64), AlertPriority::Medium);
    assert_eq!(AlertPriority::from_score(0.65), AlertPriority::High);
    assert_eq!(AlertPriority::from_score(0.84), AlertPriority::High);
    assert_eq!(AlertPriority::from_score(0.85), AlertPriority::Critical);
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
        whitelist_matches: 0,
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
    // FlashLoanSignature alone is now blocked (solo-trigger guard).
    // Score exactly at threshold with a non-flash-loan reason → flagged.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        min_gas_used: 500_000,
        gas_ratio_threshold: 0.95,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // UnusualGasPattern alone = 0.15 == threshold → flagged
    let receipt = make_receipt(true, 990_000, vec![]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
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

// ---------------------------------------------------------------------------
// Reentrancy PreFilter tests
// ---------------------------------------------------------------------------

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
