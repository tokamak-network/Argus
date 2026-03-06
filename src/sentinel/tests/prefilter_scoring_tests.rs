//! PreFilter scoring model tests: integration, relevance gate, min signals, cash flow, reentrancy.

use super::*;

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
    // TX1 has flash loan + known contract → 1 independent signal → blocked by min-2-signals.
    // So 0 suspicious TXs in this block.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // TX 0: benign simple transfer
    let tx0 = make_tx_call(random_address(0x01), U256::from(100), 21_000);
    let r0 = make_receipt(true, 21_000, vec![]);

    // TX 1: flash loan topic to known contract (Aave) → 1 independent signal
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
    assert_eq!(result.len(), 0);
}

#[test]
fn test_combined_flash_loan_plus_transfers() {
    // Flash loan + 7 ERC-20 transfers + known contract (Aave V2).
    // Independent signals: 2 (flash, erc20) — passes min-2-signals.
    // base_score = 0.4 + 0.2 + 0.0 = 0.6
    // relevance_factor = 0.3 (known contract present)
    // score = 0.6 * 0.3 = 0.18
    // Need low threshold to verify detection.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        mev_flash_loan_factor: 1.0, // disable MEV suppression for heuristic test
        ..Default::default()
    });
    let header = make_header(19_500_000);

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
    // Score = (0.4 + 0.2) * 0.3 = 0.18
    assert!(stx.score > 0.1);
}

#[test]
fn test_threshold_boundary_exact() {
    // UnusualGasPattern alone: 1 independent signal. Use min_independent_signals=1.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.15,
        min_gas_used: 500_000,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 1,
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
    // Flash loan alone: 1 independent signal → blocked by min-2-signals (default=2)
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.5,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_none());
}

#[test]
fn test_critical_priority_combined() {
    // Flash loan + 12 ERC-20 (>10) + known contract (Aave).
    // Independent signals: 2 (flash, erc20) → passes gate.
    // base_score = 0.4 + 0.4 + 0.0 = 0.8
    // relevance_factor = 0.3 (known contract)
    // score = 0.8 * 0.3 = 0.24
    // To get Critical, we need a case without known contract.
    // Test with unknown TX target to avoid relevance gate.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan from unknown provider + 12 ERC-20 transfers (no known contract)
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let mut logs: Vec<Log> = (0..12)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs.insert(0, flash_log);

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    // base_score = 0.4 + 0.4 = 0.8, no known contract → relevance = 1.0
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
// Relevance gate tests
// ---------------------------------------------------------------------------

#[test]
fn test_known_contract_relevance_gate() {
    // TX with known contract: score should be multiplied by 0.3
    // Flash loan (0.4) + ERC-20 (0.2) + known contract (0.0) to Aave
    // Without relevance gate: 0.6
    // With relevance gate: 0.6 * 0.3 = 0.18
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        ..Default::default()
    });
    let header = make_header(19_500_000);

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

    // Score should be dampened by relevance gate: ~0.18, NOT 0.6
    assert!(
        stx.score < 0.3,
        "Score with known contract should be < 0.3, got {}",
        stx.score
    );
    assert!(stx.score > 0.0);

    // Same TX without known contract → score = 0.6
    let flash_log2 = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let mut logs2: Vec<Log> = (0..7)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs2.insert(0, flash_log2);
    let receipt2 = make_receipt(true, 800_000, logs2);
    let tx2 = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result2 = filter.scan_tx(&tx2, &receipt2, 0, &header);
    assert!(result2.is_some());
    let stx2 = result2.unwrap();
    assert!(
        stx2.score > 0.5,
        "Score without known contract should be > 0.5, got {}",
        stx2.score
    );
}

// ---------------------------------------------------------------------------
// Min 2 independent signals tests
// ---------------------------------------------------------------------------

#[test]
fn test_min_two_independent_signals() {
    // A TX with only 1 independent signal should NOT be flagged (default min=2)
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan only → 1 independent signal (flash)
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let receipt = make_receipt(true, 500_000, vec![log]);
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(
        result.is_none(),
        "Single signal should be blocked by min-2-signals gate"
    );

    // Same TX with min_independent_signals=1 → should be flagged
    let filter2 = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        min_independent_signals: 1,
        ..Default::default()
    });
    let log2 = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let receipt2 = make_receipt(true, 500_000, vec![log2]);
    let tx2 = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result2 = filter2.scan_tx(&tx2, &receipt2, 0, &header);
    assert!(
        result2.is_some(),
        "With min_independent_signals=1, single signal should pass"
    );
}

// ---------------------------------------------------------------------------
// Min-2-signals combination tests (gate integration)
// ---------------------------------------------------------------------------

#[test]
fn test_two_signals_flash_plus_erc20_passes_gate() {
    // Flash loan (H1) + 7 ERC-20 transfers (H3) = 2 independent signals → passes gate
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.1,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(random_address(0xAA), vec![aave_topic], Bytes::new());
    let mut logs: Vec<Log> = (0..7)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs.insert(0, flash_log);

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(
        result.is_some(),
        "flash + erc20 = 2 signals should pass the min-2 gate"
    );
}

#[test]
fn test_two_signals_revert_plus_selfdestruct_passes_gate() {
    // High-value revert (H2) + self-destruct (H6) = 2 independent signals → passes gate
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.2,
        mev_selfdestruct_factor: 1.0, // disable MEV suppression for heuristic test
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Reverted, high gas (>1M), empty logs, high value
    let receipt = make_receipt(false, 2_000_000, vec![]);
    let tx = make_tx_call(random_address(0x01), one_eth() * 5, 3_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(
        result.is_some(),
        "revert + selfdestruct = 2 signals should pass the min-2 gate"
    );
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::HighValueWithRevert { .. }))
    );
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::SelfDestructDetected))
    );
}

#[test]
fn test_two_signals_gas_plus_oracle_passes_gate() {
    // Unusual gas (H5) + oracle+dex (H7) = 2 independent signals → passes gate
    // Also fires H4 (known contract) but that doesn't count.
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        min_independent_signals: 2,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    let oracle_log = make_log(chainlink_eth_usd(), vec![H256::zero()], Bytes::new());
    let dex_log = make_log(uniswap_v3_router(), vec![H256::zero()], Bytes::new());
    let receipt = make_receipt(true, 990_000, vec![oracle_log, dex_log]);
    // gas_used/gas_limit = 990k/1M = 0.99 > 0.95 and > 500k → H5 fires
    let tx = make_tx_call(random_address(0x01), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(
        result.is_some(),
        "gas + oracle = 2 signals should pass the min-2 gate"
    );
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::UnusualGasPattern { .. }))
    );
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::PriceOracleWithSwap { .. }))
    );
}

// ---------------------------------------------------------------------------
// Cash flow symmetry tests (H8)
// ---------------------------------------------------------------------------

#[test]
fn test_cash_flow_symmetric_discount() {
    // Flash loan with symmetric cash flow: provider gets repaid in second half
    // → symmetry_factor = config.symmetry_discount → score reduced
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    // Flash loan provider = 0xAA
    let provider = random_address(0xAA);
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(provider, vec![aave_topic], Bytes::new());

    let user_addr = random_address(0x60);

    // First half: provider → user (borrow)
    let mut logs = vec![flash_log];
    for _ in 0..4 {
        logs.push(make_erc20_transfer_log(provider, user_addr));
    }
    // Second half: user → provider (repay — provider appears in destinations)
    for _ in 0..4 {
        logs.push(make_erc20_transfer_log(user_addr, provider));
    }

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    let symmetric_score = stx.score;

    // Verify no AsymmetricCashFlow reason
    assert!(
        !stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::AsymmetricCashFlow { .. })),
        "Symmetric flow should NOT have AsymmetricCashFlow reason"
    );

    // Compare with asymmetric version (funds go to drain, NOT back to provider)
    let flash_log2 = make_log(provider, vec![aave_topic], Bytes::new());
    let mut logs2 = vec![flash_log2];
    for _ in 0..4 {
        logs2.push(make_erc20_transfer_log(provider, user_addr));
    }
    // Second half goes to a DIFFERENT address (not provider)
    for _ in 0..4 {
        logs2.push(make_erc20_transfer_log(user_addr, random_address(0x99)));
    }

    let receipt2 = make_receipt(true, 800_000, logs2);
    let tx2 = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result2 = filter.scan_tx(&tx2, &receipt2, 0, &header);
    assert!(result2.is_some());
    let asymmetric_score = result2.unwrap().score;

    assert!(
        symmetric_score < asymmetric_score,
        "Symmetric score ({symmetric_score}) should be less than asymmetric ({asymmetric_score})"
    );
}

#[test]
fn test_cash_flow_asymmetric_adds_reason() {
    // Flash loan with asymmetric cash flow: funds flow to drain address, not back to provider
    // → should add AsymmetricCashFlow reason
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    let provider = random_address(0xAA);
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(provider, vec![aave_topic], Bytes::new());

    let user_addr = random_address(0x60);
    let drain_addr = random_address(0x99);

    // First half: provider → user (borrow)
    let mut logs = vec![flash_log];
    for _ in 0..4 {
        logs.push(make_erc20_transfer_log(provider, user_addr));
    }
    // Second half: user → drain (drain != provider, asymmetric)
    for _ in 0..4 {
        logs.push(make_erc20_transfer_log(user_addr, drain_addr));
    }

    let receipt = make_receipt(true, 800_000, logs);
    let tx = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::AsymmetricCashFlow { .. })),
        "Asymmetric flow should add AsymmetricCashFlow reason"
    );
}

#[test]
fn test_cash_flow_single_transfer_not_applicable() {
    // Flash loan with only 1 ERC-20 transfer → too few to determine symmetry → NotApplicable
    // Should NOT inject AsymmetricCashFlow reason
    let filter = PreFilter::new(SentinelConfig {
        suspicion_threshold: 0.01,
        min_independent_signals: 1,
        ..Default::default()
    });
    let header = make_header(19_500_000);

    let provider = random_address(0xAA);
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(provider, vec![aave_topic], Bytes::new());
    let transfer = make_erc20_transfer_log(provider, random_address(0x60));

    let receipt = make_receipt(true, 500_000, vec![flash_log, transfer]);
    let tx = make_tx_call(random_address(0xBB), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header);
    assert!(result.is_some());
    let stx = result.unwrap();
    assert!(
        !stx.reasons
            .iter()
            .any(|r| matches!(r, SuspicionReason::AsymmetricCashFlow { .. })),
        "Single transfer should NOT trigger AsymmetricCashFlow"
    );
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
        let filter = PreFilter::new(SentinelConfig {
            mev_selfdestruct_factor: 1.0, // disable MEV suppression for heuristic test
            ..Default::default()
        });

        // Construct a reverted TX with 5 ETH value + 2M gas + no logs.
        // H2 (high value revert): 5 ETH > 1 ETH threshold, reverted, gas=2M > 100k → score 0.3
        // H6 (self-destruct indicators): reverted, gas > 1M, empty logs → score 0.3
        // Independent signals: 2 (revert, selfdestruct) → passes min-2-signals
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

// ---------------------------------------------------------------------------
// MEV pattern suppression tests
// ---------------------------------------------------------------------------

mod mev_pattern_tests {
    use super::*;

    #[test]
    fn mev_flash_loan_arbitrage_suppressed() {
        // Exact fingerprint of Fargate false positives:
        // FlashLoan(Balancer) + ERC20(22 transfers) + KnownContract + UnusualGas
        // Base: 0.40 + 0.40 + 0.15 = 0.95
        // After MEV factor 0.15: 0.95 * 0.15 = 0.1425 → below 0.70
        let filter = PreFilter::new(SentinelConfig {
            suspicion_threshold: 0.70,
            min_erc20_transfers: 20,
            relevance_factor: 1.0, // worst-case: no relevance dampening
            mev_flash_loan_factor: 0.15,
            ..Default::default()
        });
        let header = make_header(21_000_000);

        // Balancer Vault flash loan log
        let balancer_addr = balancer_vault();
        let flash_topic = H256::from_slice(&{
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&[0x0d, 0x7d, 0x75, 0xe0]);
            bytes
        });
        let flash_log = make_log(balancer_addr, vec![flash_topic], Bytes::new());

        // 22 ERC-20 transfers
        let mut logs: Vec<Log> = (0u8..22)
            .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
            .collect();
        logs.insert(0, flash_log);

        // Unusual gas: 980k/1M = 0.98 > 0.95
        let receipt = make_receipt(true, 980_000, logs);
        let tx = make_tx_call(balancer_addr, U256::zero(), 1_000_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_none(),
            "Balancer flash loan MEV must be suppressed below 0.70 threshold"
        );
    }

    #[test]
    fn mev_selfdestruct_cleanup_suppressed() {
        // Exact fingerprint of SelfDestruct false positives:
        // HighValueRevert(0.30) + SelfDestruct(0.30) + UnusualGas(0.15) = 0.75
        // After MEV factor 0.25: 0.75 * 0.25 = 0.1875 → below 0.70
        let filter = PreFilter::new(SentinelConfig {
            suspicion_threshold: 0.70,
            mev_selfdestruct_factor: 0.25,
            ..Default::default()
        });
        let header = make_header(21_000_000);

        // Reverted, high ETH, high gas > 1M, empty logs (self-destruct pattern)
        let receipt = make_receipt(false, 2_000_000, vec![]);
        let tx = make_tx_call(random_address(0xCC), one_eth() * 5, 3_000_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_none(),
            "SelfDestruct + HighValueRevert without flash loan must be suppressed"
        );
    }

    #[test]
    fn genuine_flash_loan_from_unknown_provider_not_suppressed() {
        // Flash loan from UNKNOWN provider (not in known_address_db).
        // No KnownContractInteraction → MEV flash loan filter does NOT fire.
        let filter = PreFilter::new(SentinelConfig {
            suspicion_threshold: 0.50,
            min_erc20_transfers: 5,
            mev_flash_loan_factor: 0.15,
            relevance_factor: 1.0, // no relevance dampening
            ..Default::default()
        });
        let header = make_header(21_000_000);

        // Flash loan from unknown provider
        let unknown_provider = random_address(0xDE);
        let flash_topic = H256::from_slice(&{
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&[0x0d, 0x7d, 0x75, 0xe0]); // Balancer-style topic
            bytes
        });
        let flash_log = make_log(unknown_provider, vec![flash_topic], Bytes::new());

        // 8 ERC-20 transfers (above min_erc20_transfers=5)
        let mut logs = vec![flash_log];
        for i in 0u8..8 {
            logs.push(make_erc20_transfer_log(
                random_address(i),
                random_address(i + 50),
            ));
        }

        let receipt = make_receipt(true, 900_000, logs);
        let tx = make_tx_call(unknown_provider, U256::zero(), 1_000_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_some(),
            "Flash loan from unknown provider must NOT be suppressed by MEV filter"
        );
    }

    #[test]
    fn flash_loan_plus_selfdestruct_not_suppressed() {
        // Flash loan + SelfDestruct combo = real attack vector.
        // SelfDestructCleanup requires !has_flash_loan, so this is NOT suppressed.
        let filter = PreFilter::new(SentinelConfig {
            suspicion_threshold: 0.50,
            min_independent_signals: 2,
            mev_selfdestruct_factor: 0.25,
            mev_flash_loan_factor: 0.15,
            relevance_factor: 1.0,
            ..Default::default()
        });
        let header = make_header(21_000_000);

        // Flash loan log from unknown provider
        let unknown_provider = random_address(0xDE);
        let flash_topic = H256::from_slice(&{
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&[0x0d, 0x7d, 0x75, 0xe0]);
            bytes
        });
        let flash_log = make_log(unknown_provider, vec![flash_topic], Bytes::new());

        // Reverted + high value + high gas (triggers H2 + H6) + flash loan (H1)
        let receipt = make_receipt(false, 2_000_000, vec![flash_log]);
        let tx = make_tx_call(random_address(0xBB), one_eth() * 3, 3_000_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_some(),
            "Flash loan + SelfDestruct combo must NOT be suppressed"
        );
    }

    #[test]
    fn mev_factors_disabled_at_1_0_pass_through() {
        // With mev_*_factor = 1.0, Balancer MEV passes unchanged
        let filter = PreFilter::new(SentinelConfig {
            suspicion_threshold: 0.70,
            min_erc20_transfers: 20,
            relevance_factor: 1.0,
            mev_flash_loan_factor: 1.0,   // disabled
            mev_selfdestruct_factor: 1.0, // disabled
            ..Default::default()
        });
        let header = make_header(21_000_000);

        let balancer_addr = balancer_vault();
        let flash_topic = H256::from_slice(&{
            let mut bytes = [0u8; 32];
            bytes[..4].copy_from_slice(&[0x0d, 0x7d, 0x75, 0xe0]);
            bytes
        });
        let flash_log = make_log(balancer_addr, vec![flash_topic], Bytes::new());

        let mut logs: Vec<Log> = (0u8..22)
            .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
            .collect();
        logs.insert(0, flash_log);

        let receipt = make_receipt(true, 980_000, logs);
        let tx = make_tx_call(balancer_addr, U256::zero(), 1_000_000);

        let result = filter.scan_tx(&tx, &receipt, 0, &header);
        assert!(
            result.is_some(),
            "With MEV factors disabled (1.0), Balancer flash loan must still be flagged"
        );
    }
}
