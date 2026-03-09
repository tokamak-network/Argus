//! PreFilter heuristic tests: H1–H8, config, threshold, integration.

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
    assert_eq!(config.min_independent_signals, 2);
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
    // KnownContractInteraction now scores 0.0 (relevance modifier only)
    assert!(
        SuspicionReason::KnownContractInteraction {
            address: Address::zero(),
            label: String::new()
        }
        .score()
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
    // AsymmetricCashFlow scores 0.2
    assert!(
        (SuspicionReason::AsymmetricCashFlow {
            unique_destinations: 3
        }
        .score()
            - 0.2)
            .abs()
            < f64::EPSILON
    );
    // AccessControlBypass returns its inner score
    assert!(
        (SuspicionReason::AccessControlBypass { score: 0.3 }.score() - 0.3).abs() < f64::EPSILON
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
    // Flash loan + known contract (Aave) fires H1 + H4.
    // Independent signals = 1 (flash only, H4 excluded) → blocked by min-2-signals.
    // Score = 0.4 * 0.3 (relevance) = 0.12 → need low threshold.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
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
    // Balancer flash loan + known contract. Score = 0.4 * 0.3 = 0.12.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
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
    // Uniswap V3 flash + known contract. H1(flash) + H4(known).
    // Independent signals = 1 → blocked by default min-2-signals.
    // Score = 0.4 * 0.3 = 0.12 → need low threshold.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
    let uni_topic = topic_with_prefix([0xbd, 0xbd, 0xb7, 0x16]);
    let log = make_log(random_address(0x33), vec![uni_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(uniswap_v3_router(), U256::zero(), 1_000_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    // Score = 0.4 * 0.3 (relevance gate) = 0.12. Known contract score is 0.0.
    let stx = result.unwrap();
    assert!(stx.score > 0.0);
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

    // H2 alone = 0.3, independent signals = 1 (revert), below min-2-signals → not flagged
    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_high_value_revert_with_lower_threshold() {
    // H2 alone: independent signals = 1. Need min_independent_signals=1.
    let config = SentinelConfig {
        suspicion_threshold: 0.2,
        min_independent_signals: 1,
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
    // H3 alone: independent = 1. Need min_independent_signals=1 to test.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        min_independent_signals: 1,
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
    // H3 alone: independent = 1. Need min_independent_signals=1.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        min_independent_signals: 1,
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
    // H4 alone has 0 independent signals → always returns None.
    // Use min_independent_signals=0 to verify reason is still collected.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.0,
        min_independent_signals: 0,
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
    // Score = 0.0 * 0.3 (relevance) = 0.0
    assert!(stx.score.abs() < f64::EPSILON);
}

#[test]
fn test_known_contract_in_logs() {
    // H4 alone: 0 independent signals. Use min_independent_signals=0.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.0,
        min_independent_signals: 0,
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
    // H5 alone: independent = 1. Need min_independent_signals=1.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
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
    // H2 (high value revert) + H6 (self-destruct): 2 independent signals → passes gate
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.2,
        mev_selfdestruct_factor: 1.0, // disable MEV suppression for heuristic test
        ..Default::default()
    });
    // Reverted, high gas (>1M), empty logs, high value
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
    // H4(known: Chainlink + Uniswap) + H7(oracle+dex).
    // Independent signals = 1 (oracle). Need min_independent_signals=1.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        min_independent_signals: 1,
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
    // H4 fires (known contract: Chainlink) but score = 0.0, independent = 0 → None
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// TOML config parsing: verify MEV defaults from Fargate-style TOML
// ---------------------------------------------------------------------------

#[test]
fn test_toml_fargate_mev_defaults() {
    use crate::sentinel::config::load_config;

    let toml_content = "\
[sentinel]\n\
enabled = true\n\
\n\
[sentinel.prefilter]\n\
suspicion_threshold = 0.7\n\
min_value_eth = 1.0\n\
min_erc20_transfers = 20\n\
gas_ratio_threshold = 0.98\n\
\n\
[sentinel.analysis]\n\
max_steps = 500000\n\
min_alert_confidence = 0.6\n\
prefilter_alert_mode = false\n\
\n\
[sentinel.alert]\n\
rate_limit_per_minute = 10\n\
dedup_window_blocks = 5\n\
";

    let path = std::path::PathBuf::from("/tmp/test_fargate_mev.toml");
    std::fs::write(&path, toml_content).unwrap();

    let config = load_config(Some(&path)).expect("should parse TOML");
    let sc = config.to_sentinel_config();

    assert!(
        (sc.mev_flash_loan_factor - 0.15).abs() < f64::EPSILON,
        "mev_flash_loan_factor should default to 0.15, got {}",
        sc.mev_flash_loan_factor
    );
    assert!(
        (sc.mev_selfdestruct_factor - 0.25).abs() < f64::EPSILON,
        "mev_selfdestruct_factor should default to 0.25, got {}",
        sc.mev_selfdestruct_factor
    );
}

// ---------------------------------------------------------------------------
// Access control bypass tests (H9)
// ---------------------------------------------------------------------------

/// ACB fires when: success + gas < 100k + known DeFi + >= 3 ERC-20 transfers.
#[test]
fn test_acb_detected_low_gas_known_defi_multiple_transfers() {
    // H9(ACB) = +0.3, H4(known) = 0.0. With relevance factor 0.3: 0.3 * 0.3 = 0.09.
    // Need threshold <= 0.09 or disable relevance factor.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.05,
        min_independent_signals: 1,
        relevance_factor: 1.0, // disable relevance dampening for isolated H9 test
        min_erc20_transfers: 5, // only H3 fires at >=5, but ACB checks >=3 internally
        ..Default::default()
    });
    // 4 ERC-20 transfer logs from Aave V2 pool (known DeFi)
    let logs: Vec<Log> = (0..4)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    // Low gas, success, to known DeFi contract
    let receipt = make_receipt(true, 80_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 100_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some(), "ACB should be detected");
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::AccessControlBypass { .. })),
        "Should contain AccessControlBypass reason"
    );
}

/// ACB does not fire for reverted TX.
#[test]
fn test_acb_not_detected_on_revert() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
    let logs: Vec<Log> = (0..4)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    // Reverted TX
    let receipt = make_receipt(false, 80_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 100_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    // Should not fire ACB (reverted)
    if let Some(stx) = result {
        assert!(
            !stx.reasons
                .iter()
                .any(|r| matches!(r, SuspicionReason::AccessControlBypass { .. })),
            "ACB should not fire on reverted TX"
        );
    }
}

/// ACB does not fire when gas >= 100k.
#[test]
fn test_acb_not_detected_high_gas() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
    let logs: Vec<Log> = (0..4)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    // Gas >= 100k
    let receipt = make_receipt(true, 150_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 200_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    if let Some(stx) = result {
        assert!(
            !stx.reasons
                .iter()
                .any(|r| matches!(r, SuspicionReason::AccessControlBypass { .. })),
            "ACB should not fire when gas >= 100k"
        );
    }
}

/// ACB does not fire with fewer than 3 ERC-20 transfers.
#[test]
fn test_acb_not_detected_few_transfers() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
    // Only 2 transfers
    let logs: Vec<Log> = (0..2)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    let receipt = make_receipt(true, 80_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 100_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    if let Some(stx) = result {
        assert!(
            !stx.reasons
                .iter()
                .any(|r| matches!(r, SuspicionReason::AccessControlBypass { .. })),
            "ACB should not fire with < 3 transfers"
        );
    }
}

/// ACB does not fire for unknown contracts.
#[test]
fn test_acb_not_detected_unknown_contract() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        min_independent_signals: 1,
        ..Default::default()
    });
    let logs: Vec<Log> = (0..4)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    // Unknown contract (not in known DeFi list)
    let receipt = make_receipt(true, 80_000, logs);
    let tx = make_tx_call(random_address(0xFF), U256::zero(), 100_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    if let Some(stx) = result {
        assert!(
            !stx.reasons
                .iter()
                .any(|r| matches!(r, SuspicionReason::AccessControlBypass { .. })),
            "ACB should not fire for unknown contracts"
        );
    }
}

/// ACB score contribution is ACB_FACTOR (0.3).
#[test]
fn test_acb_score_contribution() {
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        min_independent_signals: 1,
        relevance_factor: 1.0, // disable relevance dampening
        ..Default::default()
    });
    // 4 transfers from known DeFi, low gas, success
    let logs: Vec<Log> = (0..4)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    let receipt = make_receipt(true, 80_000, logs);
    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 100_000);
    let header = make_header(19_500_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    let acb_reason = stx
        .reasons
        .iter()
        .find(|r| matches!(r, SuspicionReason::AccessControlBypass { .. }));
    assert!(acb_reason.is_some());
    if let SuspicionReason::AccessControlBypass { score } = acb_reason.unwrap() {
        assert!(
            (*score - 0.3).abs() < f64::EPSILON,
            "ACB score should be 0.3, got {score}"
        );
    }
}
