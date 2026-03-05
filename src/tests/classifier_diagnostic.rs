//! Diagnostic tests for AttackClassifier flash loan detection.
//!
//! These tests isolate each flash loan strategy to determine the exact
//! failure point when processing Balancer-style flash loan traces.

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::types::AttackPattern;
use crate::tests::classifier_helpers::*;
use crate::types::StepRecord;
use ethrex_common::U256;

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
    // Strategy 1 produces FlashLoan with token=None, provider=None (ETH value only).
    // Strategy 2 produces FlashLoan with token=Some(..) (ERC-20 transfer matching).
    let eth_only_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { token: None, .. }))
        .collect();

    // EXPECTED: No Strategy 1 match (ETH-based flash loan)
    assert!(
        eth_only_flash_loans.is_empty(),
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
    let _pool = addr(0xB);
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

/// Strategy 3 detects when >40% of steps are at depth > entry_depth + 1.
/// This works for flash loan callbacks where most work happens inside the callback.
#[test]
fn diag_strategy3_works_at_65pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 5 steps at depth 0-1 (shallow)
    steps.push(make_call_step(0, 0, attacker, pool, U256::zero()));
    steps.push(make_step(1, 0x01, 1, pool));
    steps.push(make_call_step(2, 1, pool, attacker, U256::zero()));

    // 65 steps at depth 2 (deep callback) — 65% of 100
    // Requires 2+ SSTOREs for Strategy 3 to fire
    for i in 3..68 {
        if i == 30 || i == 50 {
            steps.push(make_sstore_step_simple(i, 2, target));
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

/// Strategy 3 detects when deep ratio is 48% (above lowered 40% threshold).
#[test]
fn diag_strategy3_detects_at_48pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    for i in 0..10 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(10, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(11, 1, pool, attacker, U256::zero()));

    // 48 steps at depth 2 (48% — above 40% threshold)
    for i in 12..60 {
        if i == 30 || i == 45 {
            steps.push(make_sstore_step_simple(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    for i in 60..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let callback_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();

    assert!(
        !callback_flash_loans.is_empty(),
        "Strategy 3 should detect when deep ratio is 48% (above 40% threshold). Got: {patterns:?}"
    );
}

/// Strategy 3 FAILS when deep ratio is below 40% (28%).
#[test]
fn diag_strategy3_fails_at_28pct_depth_ratio() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    for i in 0..10 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(10, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(11, 1, pool, attacker, U256::zero()));

    // 28 steps at depth 2 (28% — well below 40%)
    for i in 12..40 {
        if i == 25 || i == 35 {
            steps.push(make_sstore_step_simple(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    for i in 40..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let patterns = AttackClassifier::classify(&steps);
    let callback_flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();

    assert!(
        callback_flash_loans.is_empty(),
        "Strategy 3 should NOT detect when deep ratio is 28%. Got: {patterns:?}"
    );
}

// ── Boundary tests: precise 40% threshold validation ──

/// Exactly 41 of 100 steps at depth 2 → 41% > 40% threshold → detected.
#[test]
fn diag_strategy3_passes_at_41pct_boundary() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 9 shallow steps (depth 0-1)
    for i in 0..7 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(7, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(8, 1, pool, attacker, U256::zero()));

    // 41 deep steps at depth 2 (index 9..50) → 41%
    for i in 9..50 {
        if i == 20 || i == 35 {
            steps.push(make_sstore_step_simple(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // 50 shallow steps (depth 0)
    for i in 50..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let deep = steps.iter().filter(|s| s.depth > 1).count();
    assert_eq!(deep, 41, "fixture sanity: expected 41 deep steps");

    let patterns = AttackClassifier::classify(&steps);
    let has_callback = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        has_callback,
        "41% > 40% threshold: Strategy 3 should detect. Got: {patterns:?}"
    );
}

/// Exactly 39 of 100 steps at depth 2 → 39% < 40% threshold → NOT detected.
#[test]
fn diag_strategy3_fails_at_39pct_boundary() {
    let attacker = addr(0xA);
    let pool = addr(0xB);
    let target = addr(0xC);

    let mut steps = Vec::with_capacity(100);
    // 11 shallow steps (depth 0-1)
    for i in 0..9 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }
    steps.push(make_call_step(9, 0, attacker, pool, U256::zero()));
    steps.push(make_call_step(10, 1, pool, attacker, U256::zero()));

    // 39 deep steps at depth 2 (index 11..50) → 39%
    for i in 11..50 {
        if i == 20 || i == 35 {
            steps.push(make_sstore_step_simple(i, 2, target));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }

    // 50 shallow steps (depth 0)
    for i in 50..100 {
        steps.push(make_step(i, 0x01, 0, attacker));
    }

    let deep = steps.iter().filter(|s| s.depth > 1).count();
    assert_eq!(deep, 39, "fixture sanity: expected 39 deep steps");

    let patterns = AttackClassifier::classify(&steps);
    let has_callback = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        !has_callback,
        "39% < 40% threshold: Strategy 3 should NOT detect. Got: {patterns:?}"
    );
}

// ── Combined: Realistic Balancer Flash Loan ──

/// Simulate a realistic Balancer flash loan TX profile.
/// Validates that Strategy 2 (ERC-20 Transfer matching) detects the pattern
/// and that dedup prevents duplicate Strategy 3 matches.
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
    // Phase 2: Call to Balancer Vault (depth 0→1)
    steps.push(make_call_step(10, 0, attacker, vault, U256::zero()));
    // Phase 3: Vault setup (depth 1) — 10 steps
    for i in 11..21 {
        steps.push(make_step(i, 0x01, 1, vault));
    }
    // Phase 4: ERC-20 Transfer borrow
    steps.push(make_log3_transfer(21, 1, token, vault, attacker));
    // Phase 5: Vault calls back attacker (depth 1→2)
    steps.push(make_call_step(22, 1, vault, attacker, U256::zero()));
    // Phase 6: Callback operations (depth 2) — 100 steps (50%)
    for i in 23..123 {
        if i % 20 == 0 {
            steps.push(make_sstore_step_simple(i, 2, target));
        } else if i % 30 == 0 {
            steps.push(make_call_step(i, 2, attacker, target, U256::zero()));
        } else {
            steps.push(make_step(i, 0x01, 2, attacker));
        }
    }
    // Phase 7: Return from callback
    steps.push(make_step(123, 0xF3, 2, attacker));
    // Phase 8: Vault post-callback (depth 1) — 30 steps
    for i in 124..154 {
        steps.push(make_step(i, 0x01, 1, vault));
    }
    // Phase 9: ERC-20 Transfer repay
    steps.push(make_log3_transfer(154, 1, token, attacker, vault));
    // Phase 10: Vault cleanup + return (depth 0)
    for i in 155..200 {
        steps.push(make_step(i, if i < 175 { 0x01 } else { 0x00 }, 0, attacker));
    }

    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash_loans: Vec<_> = detected
        .iter()
        .filter(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }))
        .collect();

    assert!(
        !flash_loans.is_empty(),
        "Realistic Balancer flash loan should be detected. Got: {detected:?}"
    );

    // Verify dedup: should NOT have duplicate FlashLoan patterns for the same TX
    assert!(
        flash_loans.len() <= 2,
        "Expected at most 2 FlashLoan patterns (Strategy 2 for each token), got {}",
        flash_loans.len()
    );
}
