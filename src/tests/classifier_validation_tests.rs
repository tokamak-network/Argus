//! Classifier validation tests: Balancer flash loan profile + false-positive guards.
//!
//! Supplements exploit_smoke_tests.rs with:
//! 1. Balancer-profile flash loan (ERC-20, no ETH value, many transfers)
//! 2. High-value revert pattern
//! 3. False-positive guards (simple transfer, DEX swap, Uniswap V3 callback)
//! 4. Reentrancy with CALL depth structure
//!
//! All tests are offline — no network access required.

use ethrex_common::U256;

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::types::AttackPattern;
use crate::tests::classifier_helpers::*;
use crate::types::StepRecord;

// ── Balancer flash loan fixture ──────────────────────────────────────

/// Balancer V2 flash loan profile:
/// - Initiator calls Balancer Vault (depth 0, ETH value = 0)
/// - Vault transfers ERC-20 to initiator (LOG3 Transfer, first 30% of trace)
/// - Vault calls initiator callback (depth 1 → 2)
/// - Callback: many SSTORE + CALL operations at depth 2+ (middle ~60-70% of trace)
/// - Initiator repays ERC-20 to Vault (LOG3 Transfer, last 30% of trace)
///
/// This is the exact profile of all 61 Critical alerts from the mainnet detection report.
fn balancer_flash_loan_fixture() -> Vec<StepRecord> {
    let initiator = addr(0xA17E);
    let vault = balancer_vault();
    let token_a = addr(0xDEAD_A);
    let token_b = addr(0xDEAD_B);

    let mut steps: Vec<StepRecord> = Vec::with_capacity(120);

    // Step 0: initiator calls Balancer Vault (no ETH — flash loan is ERC-20 only)
    steps.push(make_call_step(0, 0, initiator, vault, U256::zero()));

    // Steps 1-5: Balancer Vault transfers tokens to initiator (borrow)
    steps.push(make_log3_transfer(1, 1, token_a, vault, initiator));
    steps.push(make_log3_transfer(2, 1, token_b, vault, initiator));
    steps.push(make_step(3, 0x60, 1, vault));
    steps.push(make_step(4, 0x60, 1, vault));

    // Step 5: Vault calls initiator callback
    steps.push(make_call_step(5, 1, vault, initiator, U256::zero()));

    // Steps 6-89: callback operations at depth 2 (84 steps = 70% of total 120)
    for i in 6..90 {
        match i % 20 {
            0 => steps.push(make_sstore_step(
                i,
                2,
                initiator,
                slot(i as u64),
                U256::from(i),
            )),
            10 => steps.push(make_call_step(i, 2, initiator, addr(0xBEEF), U256::zero())),
            _ => steps.push(make_step(i, 0x01, 2, initiator)),
        }
    }

    // Return from callback
    steps.push(make_step(90, 0xF3, 2, initiator));
    steps.push(make_step(91, 0xF3, 1, vault));

    // Repay: initiator transfers tokens back to Vault
    steps.push(make_log3_transfer(92, 1, token_a, initiator, vault));
    steps.push(make_log3_transfer(93, 1, token_b, initiator, vault));

    // Final cleanup
    for i in 94..120 {
        steps.push(make_step(i, 0x00, 0, initiator));
    }

    steps
}

/// High-value reverted TX profile (Category B from detection report).
fn high_value_revert_fixture() -> Vec<StepRecord> {
    let sender = addr(0xABCD);
    let target = addr(0x9999);
    let five_eth = U256::from(5_000_000_000_000_000_000u128);

    vec![
        make_call_step(0, 0, sender, target, five_eth),
        make_step(1, 0x60, 1, target),
        make_step(2, 0x60, 1, target),
        make_sstore_step(3, 1, target, slot(0), U256::from(42)),
        make_step(4, 0xFD, 1, target), // REVERT
    ]
}

/// Simple ERC-20 transfer — false positive guard.
fn simple_transfer_fixture() -> Vec<StepRecord> {
    let token = addr(0xE20C);
    let from = addr(0xA1);
    let to = addr(0xB2);

    vec![
        make_log3_transfer(0, 0, token, from, to),
        make_step(1, 0x60, 0, token),
        make_step(2, 0xF3, 0, token),
    ]
}

/// Normal DEX swap (Uniswap V2-style) — false positive guard.
fn normal_dex_swap_fixture() -> Vec<StepRecord> {
    let router = addr(0xCC01);
    let token_in = addr(0xCC02);
    let token_out = addr(0xCC03);
    let user = addr(0xCC04);
    let pool = addr(0xCC05);

    vec![
        make_call_step(0, 0, user, router, U256::zero()),
        make_log3_transfer(1, 1, token_in, user, pool),
        make_step(2, 0x60, 1, pool),
        make_step(3, 0x01, 1, pool),
        make_step(4, 0x02, 1, pool),
        make_log3_transfer(5, 1, token_out, pool, user),
        make_step(6, 0xF3, 1, router),
        make_step(7, 0x00, 0, user),
    ]
}

/// Uniswap V3-style callback with deep execution — false positive guard.
///
/// V3 concentrated liquidity: user calls router → router calls pool → pool
/// calls back user's callback at depth 2 → callback does SSTORE + computation.
/// This has ~45% deep steps but is NOT a flash loan — it's a normal swap
/// with a mint/swap callback.
fn uniswap_v3_callback_fixture() -> Vec<StepRecord> {
    let user = addr(0xDD01);
    let router = addr(0xDD02);
    let pool = addr(0xDD03);
    let token = addr(0xDD04);

    let mut steps = Vec::with_capacity(100);

    // Phase 1: user → router (depth 0) — 5 steps
    steps.push(make_call_step(0, 0, user, router, U256::zero()));
    for i in 1..5 {
        steps.push(make_step(i, 0x01, 1, router));
    }

    // Phase 2: router → pool (depth 1) — 5 steps
    steps.push(make_call_step(5, 1, router, pool, U256::zero()));
    for i in 6..10 {
        steps.push(make_step(i, 0x01, 1, pool));
    }

    // Phase 3: pool → user callback (depth 2) — 45 steps (45%)
    steps.push(make_call_step(10, 1, pool, user, U256::zero()));
    for i in 11..55 {
        if i == 20 {
            // Callback does SSTORE (e.g., updating user's position)
            steps.push(make_sstore_step_simple(i, 2, user));
        } else if i == 30 {
            // Callback transfers token to pool (the payment)
            steps.push(make_log3_transfer(i, 2, token, user, pool));
        } else {
            steps.push(make_step(i, 0x01, 2, user));
        }
    }

    // Phase 4: return from callback → pool finishes (depth 1) — 20 steps
    for i in 55..75 {
        if i == 60 {
            steps.push(make_sstore_step(i, 1, pool, slot(1), U256::from(999)));
        } else {
            steps.push(make_step(i, 0x01, 1, pool));
        }
    }

    // Phase 5: pool sends output token to user (not same token as input)
    steps.push(make_log3_transfer(75, 1, addr(0xDD05), pool, user));

    // Phase 6: return to router + user (depth 0) — 24 steps
    for i in 76..100 {
        steps.push(make_step(i, 0x01, 0, user));
    }

    steps
}

/// Reentrancy fixture with explicit CALL depth structure.
fn reentrancy_with_sstore_fixture() -> Vec<StepRecord> {
    let victim = addr(0xDA0);
    let attacker = addr(0x666);
    let one_eth = U256::from(1_000_000_000_000_000_000u128);

    vec![
        make_call_step(0, 0, victim, attacker, one_eth),
        make_step(1, 0x60, 1, attacker),
        make_step(2, 0x60, 1, attacker),
        make_call_step(3, 1, attacker, victim, U256::zero()),
        make_step(4, 0x54, 2, victim), // SLOAD
        make_step(5, 0x60, 2, victim),
        make_sstore_step(6, 2, victim, slot(0), U256::zero()),
        make_step(7, 0xF3, 2, victim),
        make_step(8, 0xF3, 1, attacker),
        make_step(9, 0x00, 0, victim),
    ]
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn test_classifier_detects_balancer_flash_loan() {
    let steps = balancer_flash_loan_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        has_flash_loan,
        "Balancer ERC-20 flash loan should be detected; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_balancer_flash_loan_confidence() {
    let steps = balancer_flash_loan_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }));
    assert!(flash.is_some(), "Balancer flash loan must be detected");
    assert!(
        flash.unwrap().confidence >= 0.5,
        "Flash loan confidence should be >= 0.5, got {}",
        flash.unwrap().confidence
    );
}

#[test]
fn test_classifier_high_value_revert_no_false_flash_loan() {
    let steps = high_value_revert_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        !has_flash_loan,
        "High-value revert should not produce FlashLoan; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_no_false_positive_simple_transfer() {
    let steps = simple_transfer_fixture();
    let patterns = AttackClassifier::classify(&steps);
    assert!(
        patterns.is_empty(),
        "Simple ERC-20 transfer must produce no patterns; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_no_false_positive_dex_swap() {
    let steps = normal_dex_swap_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        !has_flash_loan,
        "Normal DEX swap must not be detected as flash loan; got: {patterns:?}"
    );
}

/// Uniswap V3 callback with ~45% deep steps + SSTORE must NOT trigger
/// Strategy 3 flash loan detection. The callback is a normal swap mechanism,
/// not a flash loan. This guards against the lowered 40% threshold producing
/// false positives on callback-heavy normal DeFi TXs.
#[test]
fn test_classifier_no_false_positive_uniswap_v3_callback() {
    let steps = uniswap_v3_callback_fixture();

    // Verify the fixture has the expected deep ratio (should be ~45%)
    let total = steps.len();
    let deep = steps.iter().filter(|s| s.depth > 1).count();
    let deep_ratio = deep as f64 / total as f64;
    assert!(
        deep_ratio > 0.4 && deep_ratio < 0.5,
        "Fixture sanity: expected ~45% deep, got {deep_ratio:.2} ({deep}/{total})"
    );

    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));

    // Strategy 2: different tokens in/out → no same-token borrow→repay match.
    // Strategy 3: deep ratio > 40%, but only 1 SSTORE at depth 2 — below the
    // minimum of 2 inner SSTOREs required to distinguish flash loan exploitation
    // from normal callbacks. Therefore no FlashLoan pattern should be produced.
    assert!(
        !has_flash_loan,
        "Uniswap V3 callback must not be detected as flash loan; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_detects_reentrancy_with_depth() {
    let steps = reentrancy_with_sstore_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_reentrancy = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::Reentrancy { .. }));
    assert!(
        has_reentrancy,
        "Reentrancy with CALL depth + SSTORE should be detected; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_reentrancy_confidence_with_sstore() {
    let steps = reentrancy_with_sstore_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let reentrancy = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));
    assert!(reentrancy.is_some(), "Reentrancy must be detected");
    assert!(
        reentrancy.unwrap().confidence >= 0.7,
        "Reentrancy with SSTORE confidence should be >= 0.7, got {}",
        reentrancy.unwrap().confidence
    );
}

#[test]
fn test_classifier_balancer_flash_loan_has_token_evidence() {
    let steps = balancer_flash_loan_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }));
    assert!(flash.is_some(), "Balancer flash loan must be detected");
    if let AttackPattern::FlashLoan { token, .. } = &flash.unwrap().pattern {
        assert!(
            token.is_some(),
            "ERC-20 flash loan must record token address; token was None"
        );
    }
}

#[test]
fn test_classifier_empty_trace_produces_no_patterns() {
    let steps: Vec<StepRecord> = vec![];
    let patterns = AttackClassifier::classify(&steps);
    assert!(
        patterns.is_empty(),
        "Empty trace must produce no patterns; got: {patterns:?}"
    );
}

#[test]
fn test_classifier_short_trace_no_flash_loan() {
    let steps = vec![
        make_step(0, 0x60, 0, addr(0x1)),
        make_step(1, 0x60, 0, addr(0x1)),
        make_step(2, 0xF3, 0, addr(0x1)),
    ];
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        !has_flash_loan,
        "3-step trace should not produce flash loan; got: {patterns:?}"
    );
}
