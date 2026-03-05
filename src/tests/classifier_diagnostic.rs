//! Diagnostic tests for AttackClassifier flash loan detection.
//!
//! These tests isolate each flash loan strategy to determine the exact
//! failure point when processing Balancer-style flash loan traces.

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::types::AttackPattern;
use crate::types::{StepRecord, StorageWrite};
use ethrex_common::{Address, H256, U256};

// ── Helpers ──────────────────────────────────────────────────

fn addr(id: u64) -> Address {
    Address::from_low_u64_be(id)
}

fn transfer_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xdd;
    bytes[1] = 0xf2;
    bytes[2] = 0x52;
    bytes[3] = 0xad;
    H256::from(bytes)
}

fn addr_to_topic(a: Address) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(a.as_bytes());
    H256::from(bytes)
}

fn make_step(index: usize, opcode: u8, depth: usize, code_address: Address) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode,
        depth,
        gas_remaining: 1_000_000 - (index as i64 * 10),
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

fn make_call_step(
    index: usize,
    depth: usize,
    from: Address,
    to: Address,
    value: U256,
) -> StepRecord {
    let to_u256 = U256::from_big_endian(to.as_bytes());
    StepRecord {
        opcode: 0xF1, // CALL
        stack_top: vec![U256::from(100_000), to_u256, value],
        stack_depth: 7,
        code_address: from,
        call_value: if value > U256::zero() {
            Some(value)
        } else {
            None
        },
        ..make_step(index, 0xF1, depth, from)
    }
}

fn make_sstore_step(index: usize, depth: usize, contract: Address) -> StepRecord {
    StepRecord {
        opcode: 0x55,
        stack_top: vec![U256::from(1), U256::from(42)],
        stack_depth: 2,
        storage_writes: Some(vec![StorageWrite {
            address: contract,
            slot: H256::zero(),
            old_value: U256::zero(),
            new_value: U256::from(42),
        }]),
        ..make_step(index, 0x55, depth, contract)
    }
}

fn make_log3_transfer(
    index: usize,
    depth: usize,
    token: Address,
    from: Address,
    to: Address,
) -> StepRecord {
    StepRecord {
        opcode: 0xA3,
        log_topics: Some(vec![
            transfer_topic(),
            addr_to_topic(from),
            addr_to_topic(to),
        ]),
        log_data: Some(vec![0; 32]),
        ..make_step(index, 0xA3, depth, token)
    }
}

// ── Strategy 1 Diagnostic: ETH value ──

/// Strategy 1 requires CALL with value > 0 in first 25% and last 25%.
/// Balancer uses ERC-20 (value=0), so Strategy 1 should NEVER match.
#[test]
fn diag_strategy1_fails_for_erc20_flash_loan() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let token = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // First 25 steps (first 25%): CALL with value=0 + ERC-20 Transfer
    steps.push(make_call_step(0, 0, attacker, pool, U256::zero()));
    steps.push(make_log3_transfer(1, 1, token, pool, attacker));
    for i in 2..25 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }
    // Middle 50 steps: operations at depth 2
    for i in 25..75 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }
    // Last 25 steps: ERC-20 repay (no ETH value)
    steps.push(make_log3_transfer(75, 1, token, attacker, pool));
    for i in 76..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let eth_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { borrow_amount, .. } if *borrow_amount > U256::zero()))
        .collect();

    // EXPECTED: No Strategy 1 match (ETH-based flash loan)
    assert!(
        eth_flash_loans.is_empty(),
        "Strategy 1 (ETH value) should NOT match ERC-20 flash loans"
    );
}

// ── Strategy 2 Diagnostic: ERC-20 Transfer ──

/// Strategy 2 looks for Transfer(pool→attacker) in first half and
/// Transfer(attacker→pool) in second half. This should work when
/// log_topics are properly captured.
#[test]
fn diag_strategy2_works_with_proper_log_topics() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let token = addr(0xC);

    let mut steps = Vec::with_capacity(20);
    // Step 0-4 (first half): pool sends token to attacker
    steps.push(make_call_step(0, 0, attacker, pool, U256::zero()));
    steps.push(make_log3_transfer(1, 1, token, pool, attacker));
    for i in 2..5 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }
    // Step 5-9 (first half still): callback operations
    for i in 5..10 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }
    // Step 10-19 (second half): attacker repays token to pool
    steps.push(make_log3_transfer(10, 1, token, attacker, pool));
    for i in 11..20 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let erc20_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { token: Some(_), .. }))
        .collect();

    assert!(
        !erc20_flash_loans.is_empty(),
        "Strategy 2 (ERC-20) should detect flash loan when log_topics are present. Got: {patterns:?}"
    );
}

/// Strategy 2 FAILS when log_topics is None (data capture problem).
#[test]
fn diag_strategy2_fails_when_log_topics_missing() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let token = addr(0xC);

    let mut steps = Vec::with_capacity(20);
    // Step 0: borrow LOG3 but WITHOUT log_topics (simulating capture failure)
    steps.push(StepRecord {
        opcode: 0xA3,
        log_topics: None, // MISSING!
        log_data: None,
        ..make_step(0, 0xA3, 1, token)
    });
    for i in 1..10 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }
    // Step 10: repay LOG3 also without log_topics
    steps.push(StepRecord {
        opcode: 0xA3,
        log_topics: None, // MISSING!
        log_data: None,
        ..make_step(10, 0xA3, 1, token)
    });
    for i in 11..20 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let erc20_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { token: Some(_), .. }))
        .collect();

    // Strategy 2 cannot detect without log_topics
    assert!(
        erc20_flash_loans.is_empty(),
        "Strategy 2 should NOT detect when log_topics are missing"
    );
}

// ── Strategy 3 Diagnostic: Callback depth ──

/// Strategy 3 detects when >60% of steps are at depth > entry_depth + 1.
/// This works for flash loan callbacks where most work happens inside the callback.
#[test]
fn diag_strategy3_works_at_60pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 5 steps at depth 0-1 (shallow)
    steps.push(make_call_step(0, 0, attacker, pool, U256::zero()));
    steps.push(make_step(1, 0x01, 1, pool));
    steps.push(make_call_step(2, 1, pool, attacker, U256::zero()));

    // 65 steps at depth 2 (deep callback) — 65% of 100
    for i in 3..68 {
        if i == 30 {
            steps.push(make_sstore_step(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // 32 steps at depth 0 (post-callback cleanup)
    for i in 68..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let callback_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();

    assert!(
        !callback_flash_loans.is_empty(),
        "Strategy 3 should detect callback pattern with 65% deep steps. Got: {patterns:?}"
    );
}

/// Strategy 3 now detects when deep ratio is 48% (above lowered 40% threshold).
/// The threshold was lowered from 60% to 40% because real-world Balancer TXs have
/// significant pre-callback and post-callback setup/cleanup at shallow depth,
/// resulting in deep ratios around 50% that the old 60% threshold would miss.
#[test]
fn diag_strategy3_detects_at_48pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 10 steps at depth 0-1 (pre-callback)
    for i in 0..10 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(10, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(11, 1, pool, attacker, U256::zero()));

    // 48 steps at depth 2 (48% — above 40% threshold)
    for i in 12..60 {
        if i == 30 {
            steps.push(make_sstore_step(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // 40 steps at depth 0 (cleanup, post-callback)
    for i in 60..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let callback_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();

    // 48% > 40% threshold → callback detection succeeds (threshold lowered for real-world coverage)
    assert!(
        !callback_flash_loans.is_empty(),
        "Strategy 3 should detect when deep ratio is 48% (above lowered 40% threshold). Got: {patterns:?}"
    );
}

/// Strategy 3 FAILS when deep ratio is below 40% (e.g., 30%).
/// This ensures we don't detect too many false positives from normal DeFi TXs.
#[test]
fn diag_strategy3_fails_below_40pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 10 steps at depth 0-1 (pre-callback)
    for i in 0..10 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(10, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(11, 1, pool, attacker, U256::zero()));

    // 28 steps at depth 2 (28% — below 40%)
    for i in 12..40 {
        if i == 30 {
            steps.push(make_sstore_step(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // 60 steps at depth 0 (cleanup, post-callback)
    for i in 40..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let callback_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();

    // 28% < 40% threshold → no callback detection
    assert!(
        callback_flash_loans.is_empty(),
        "Strategy 3 should NOT detect when deep ratio is 28% (below 40% threshold). Got: {patterns:?}"
    );
}

// ── Combined: Realistic Balancer Flash Loan ──

/// Simulate a realistic Balancer flash loan TX profile:
/// - Entry at depth 0 (attacker TX)
/// - CALL to Balancer Vault at depth 1
/// - ERC-20 Transfer (borrow) at depth 1
/// - Callback at depth 2 (attacker operations)
/// - More operations at depth 1 (between callback and repay)
/// - ERC-20 Transfer (repay) at depth 1
/// - Return to depth 0
///
/// This test checks which strategies actually match.
#[test]
fn diag_realistic_balancer_profile_detection() {
    let attacker = addr(0xA);
    let vault = addr(0xBA12);
    let token = addr(0xDA1);
    let target = addr(0xDEF1);

    let mut steps = Vec::with_capacity(200);

    // Phase 1: Entry (depth 0) — 10 steps (5%)
    for i in 0..10 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    // Phase 2: Call to Balancer Vault (depth 0→1) — 1 step
    steps.push(make_call_step(10, 0, attacker, vault, U256::zero()));

    // Phase 3: Vault setup (depth 1) — 10 steps
    for i in 11..21 {
        steps.push(make_step(i, 0x01, 1, vault));
    }

    // Phase 4: ERC-20 Transfer borrow (depth 1) — token from vault to attacker
    steps.push(make_log3_transfer(21, 1, token, vault, attacker));

    // Phase 5: Vault calls back attacker (depth 1→2) — 1 step
    steps.push(make_call_step(22, 1, vault, attacker, U256::zero()));

    // Phase 6: Callback operations (depth 2) — 100 steps (50%)
    for i in 23..123 {
        if i % 20 == 0 {
            steps.push(make_sstore_step(i, 2, target));
        } else if i % 30 == 0 {
            steps.push(make_call_step(i, 2, attacker, target, U256::zero()));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // Phase 7: Return from callback (depth 2→1) — 1 step
    steps.push(make_step(123, 0xF3, 2, attacker));

    // Phase 8: Vault post-callback (depth 1) — 30 steps
    for i in 124..154 {
        steps.push(make_step(i, 0x01, 1, vault));
    }

    // Phase 9: ERC-20 Transfer repay (depth 1) — token from attacker to vault
    steps.push(make_log3_transfer(154, 1, token, attacker, vault));

    // Phase 10: Vault cleanup (depth 1) — 20 steps
    for i in 155..175 {
        steps.push(make_step(i, 0x01, 1, vault));
    }

    // Phase 11: Return to attacker (depth 0) — 25 steps
    for i in 175..200 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let total = steps.len();
    let deep_steps = steps.iter().filter(|s| s.depth > 1).count();
    let deep_ratio = deep_steps as f64 / total as f64;

    // Diagnostic info
    eprintln!("=== Balancer Flash Loan Diagnostic ===");
    eprintln!("Total steps: {total}");
    eprintln!("Deep steps (depth > entry+1): {deep_steps}");
    eprintln!("Deep ratio: {deep_ratio:.2} (threshold: 0.60)");

    let log3_steps: Vec<_> = steps.iter().filter(|s| s.opcode == 0xA3).collect();
    eprintln!("LOG3 steps: {}", log3_steps.len());
    for s in &log3_steps {
        let has_topics = s.log_topics.is_some();
        eprintln!(
            "  step={} depth={} has_topics={} code_addr=0x{:x}",
            s.step_index, s.depth, has_topics, s.code_address
        );
    }

    // Check half boundary for Strategy 2
    let half = total / 2;
    let borrow_in_first_half = log3_steps.iter().any(|s| s.step_index < half);
    let repay_in_second_half = log3_steps.iter().any(|s| s.step_index >= half);
    eprintln!("Half boundary: step {half}");
    eprintln!("Borrow in first half: {borrow_in_first_half}");
    eprintln!("Repay in second half: {repay_in_second_half}");

    let detected = AttackClassifier::classify_with_confidence(&steps);
    eprintln!("\nDetected patterns:");
    for d in &detected {
        eprintln!("  {:?} (confidence: {:.2})", d.pattern, d.confidence);
    }

    let has_flash_loan = detected
        .iter()
        .any(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }));

    // THIS IS THE KEY ASSERTION:
    // With a realistic Balancer profile where deep_ratio < 60%,
    // Strategy 3 fails. Strategy 2 should still work if the Transfer
    // events are properly positioned in first/second halves.
    assert!(
        has_flash_loan,
        "Realistic Balancer flash loan should be detected by at least one strategy. \
         Deep ratio={deep_ratio:.2}, borrow_first_half={borrow_in_first_half}, \
         repay_second_half={repay_in_second_half}"
    );
}
