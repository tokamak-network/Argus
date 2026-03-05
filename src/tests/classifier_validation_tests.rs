//! Classifier validation tests: Balancer flash loan profile + false-positive guards.
//!
//! Supplements exploit_smoke_tests.rs with:
//! 1. Balancer-profile flash loan (ERC-20, no ETH value, many transfers)
//! 2. High-value revert pattern
//! 3. False-positive guards (simple transfer, DEX swap)
//! 4. Reentrancy with CALL depth structure
//!
//! All tests are offline — no network access required.

use ethrex_common::{Address, H256, U256};

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::types::AttackPattern;
use crate::types::{StepRecord, StorageWrite};

// ── Address helpers ──────────────────────────────────────────────────

fn addr(id: u64) -> Address {
    Address::from_low_u64_be(id)
}

fn balancer_vault() -> Address {
    // 0xBA12222222228d8Ba445958a75a0704d566BF2C8 (actual Balancer V2 Vault)
    let mut bytes = [0u8; 20];
    bytes[0] = 0xBA;
    bytes[1] = 0x12;
    bytes[2] = 0x22;
    bytes[3] = 0x22;
    Address::from_slice(&bytes)
}

fn slot(n: u64) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    H256::from(bytes)
}

fn transfer_topic() -> H256 {
    // keccak256("Transfer(address,address,uint256)") = 0xddf252ad...
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

// ── Step builder helpers ─────────────────────────────────────────────

fn make_step(index: usize, opcode: u8, depth: usize, code_address: Address) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode,
        depth,
        gas_remaining: 1_000_000 - (index as i64 * 100),
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
        step_index: index,
        pc: index * 2,
        opcode: 0xF1, // CALL
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![U256::from(100_000), to_u256, value],
        stack_depth: 7,
        memory_size: 0,
        code_address: from,
        call_value: Some(value),
        storage_writes: None,
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

fn make_sstore_step(
    index: usize,
    depth: usize,
    address: Address,
    s: H256,
    new_value: U256,
) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0x55, // SSTORE
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![],
        stack_depth: 2,
        memory_size: 0,
        code_address: address,
        call_value: None,
        storage_writes: Some(vec![StorageWrite {
            address,
            slot: s,
            old_value: U256::zero(),
            new_value,
        }]),
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

fn make_log3_transfer(
    index: usize,
    depth: usize,
    token: Address,
    from: Address,
    to: Address,
) -> StepRecord {
    let mut amount_bytes = [0u8; 32];
    // 100 tokens in the last 16 bytes
    amount_bytes[16..].copy_from_slice(&100u128.to_be_bytes());
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0xA3, // LOG3
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![],
        stack_depth: 5,
        memory_size: 64,
        code_address: token,
        call_value: None,
        storage_writes: None,
        log_topics: Some(vec![
            transfer_topic(),
            addr_to_topic(from),
            addr_to_topic(to),
        ]),
        log_data: Some(amount_bytes.to_vec()),
        call_input_selector: None,
    }
}

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
    // Multiple token transfers (typical Balancer multi-asset flash loan)
    steps.push(make_log3_transfer(1, 1, token_a, vault, initiator));
    steps.push(make_log3_transfer(2, 1, token_b, vault, initiator));
    steps.push(make_step(3, 0x60, 1, vault)); // PUSH1 (setup before callback)
    steps.push(make_step(4, 0x60, 1, vault)); // PUSH1

    // Step 5: Vault calls initiator callback (the "receiveFlashLoan" callback)
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
            _ => steps.push(make_step(i, 0x01, 2, initiator)), // ADD ops
        }
    }

    // Step 90: return from callback
    steps.push(make_step(90, 0xF3, 2, initiator)); // RETURN from callback
    steps.push(make_step(91, 0xF3, 1, vault)); // RETURN from vault call

    // Steps 92-96: repay — initiator transfers tokens back to Vault
    steps.push(make_log3_transfer(92, 1, token_a, initiator, vault));
    steps.push(make_log3_transfer(93, 1, token_b, initiator, vault));

    // Steps 94-99: final cleanup at depth 0
    for i in 94..100 {
        steps.push(make_step(i, 0x00, 0, initiator));
    }

    // Additional padding to total 120 steps, representing shallow execution at depth 0
    for i in 100..120 {
        steps.push(make_step(i, 0x60, 0, initiator));
    }

    steps
}

/// High-value reverted TX profile (Category B from detection report):
/// - Large ETH transfer CALL that reverts
/// - SSTORE before the revert
/// - No flash loan topology
fn high_value_revert_fixture() -> Vec<StepRecord> {
    let sender = addr(0xABCD);
    let target = addr(0x9999);
    let five_eth = U256::from(5_000_000_000_000_000_000u128);

    vec![
        // High-value ETH CALL (5 ETH)
        make_call_step(0, 0, sender, target, five_eth),
        make_step(1, 0x60, 1, target), // PUSH1
        make_step(2, 0x60, 1, target), // PUSH1
        // SSTORE
        make_sstore_step(3, 1, target, slot(0), U256::from(42)),
        // REVERT
        make_step(4, 0xFD, 1, target), // REVERT
    ]
}

/// Simple ERC-20 transfer — no attack pattern (false positive guard).
/// A plain transfer(address, uint256) call produces one LOG3 and returns.
fn simple_transfer_fixture() -> Vec<StepRecord> {
    let token = addr(0xE20C); // ERC-20 token contract
    let from = addr(0xA1);
    let to = addr(0xB2);

    vec![
        // Single ERC-20 Transfer event — no CALL, no deep structure
        make_log3_transfer(0, 0, token, from, to),
        make_step(1, 0x60, 0, token), // PUSH1
        make_step(2, 0xF3, 0, token), // RETURN
    ]
}

/// Normal DEX swap (Uniswap V2-style) — no attack pattern (false positive guard).
/// Single-token swap: one Transfer in, one Transfer out, shallow depth, no callback.
fn normal_dex_swap_fixture() -> Vec<StepRecord> {
    let router = addr(0xCC01); // router contract
    let token_in = addr(0xCC02);
    let token_out = addr(0xCC03);
    let user = addr(0xCC04);
    let pool = addr(0xCC05);

    vec![
        // Router called by user
        make_call_step(0, 0, user, router, U256::zero()),
        // Token in: user → pool (Transfer)
        make_log3_transfer(1, 1, token_in, user, pool),
        // Pool operations (price calculation)
        make_step(2, 0x60, 1, pool), // PUSH1
        make_step(3, 0x01, 1, pool), // ADD
        make_step(4, 0x02, 1, pool), // MUL
        // Token out: pool → user (Transfer)
        make_log3_transfer(5, 1, token_out, pool, user),
        make_step(6, 0xF3, 1, router), // RETURN
        make_step(7, 0x00, 0, user),   // STOP
    ]
}

/// Reentrancy fixture with explicit CALL depth structure.
/// Attacker re-enters victim while victim has not yet updated state.
fn reentrancy_with_sstore_fixture() -> Vec<StepRecord> {
    let victim = addr(0xDA0);
    let attacker = addr(0x666);
    let one_eth = U256::from(1_000_000_000_000_000_000u128);

    vec![
        // Victim calls attacker with 1 ETH (withdrawal)
        make_call_step(0, 0, victim, attacker, one_eth),
        // Attacker fallback executes
        make_step(1, 0x60, 1, attacker), // PUSH1
        make_step(2, 0x60, 1, attacker), // PUSH1
        // Attacker re-enters victim (the bug: victim hasn't updated state yet)
        make_call_step(3, 1, attacker, victim, U256::zero()),
        // Victim executes withdrawal again at depth 2
        make_step(4, 0x54, 2, victim), // SLOAD (read balance)
        make_step(5, 0x60, 2, victim), // PUSH
        // Victim writes balance to 0 during re-entry (state modification under re-entry)
        make_sstore_step(6, 2, victim, slot(0), U256::zero()),
        make_step(7, 0xF3, 2, victim),   // RETURN
        make_step(8, 0xF3, 1, attacker), // RETURN
        make_step(9, 0x00, 0, victim),   // STOP
    ]
}

// ── Tests ────────────────────────────────────────────────────────────

/// Balancer flash loan (ERC-20, no ETH value) must be detected.
///
/// This is the exact profile of all 61 Critical mainnet alerts.
/// Uses Strategy 2 (ERC-20 LOG3 Transfer borrow → repay matching).
#[test]
fn test_classifier_detects_balancer_flash_loan() {
    let steps = balancer_flash_loan_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        has_flash_loan,
        "Balancer ERC-20 flash loan should be detected; got patterns: {patterns:?}"
    );
}

/// Balancer flash loan confidence must be meaningful (>= 0.5).
#[test]
fn test_classifier_balancer_flash_loan_confidence() {
    let steps = balancer_flash_loan_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }));
    assert!(
        flash.is_some(),
        "Balancer flash loan must be detected; no FlashLoan in: {detected:?}"
    );
    let confidence = flash.unwrap().confidence;
    assert!(
        confidence >= 0.5,
        "Flash loan confidence should be >= 0.5, got {confidence}"
    );
}

/// High-value revert pattern should not produce a FlashLoan false positive.
/// This is a Category B alert — it may produce no patterns (just a suspicious pre-filter result).
#[test]
fn test_classifier_high_value_revert_no_false_flash_loan() {
    let steps = high_value_revert_fixture();
    let patterns = AttackClassifier::classify(&steps);
    let has_flash_loan = patterns
        .iter()
        .any(|p| matches!(p, AttackPattern::FlashLoan { .. }));
    assert!(
        !has_flash_loan,
        "Simple high-value revert should not produce a FlashLoan pattern; got: {patterns:?}"
    );
}

/// Simple ERC-20 transfer must not trigger any attack patterns.
///
/// A single transfer() call with one LOG3 event is the most common
/// non-attack transaction — this is a critical false-positive guard.
#[test]
fn test_classifier_no_false_positive_simple_transfer() {
    let steps = simple_transfer_fixture();
    let patterns = AttackClassifier::classify(&steps);
    assert!(
        patterns.is_empty(),
        "Simple ERC-20 transfer must produce no patterns; got: {patterns:?}"
    );
}

/// Normal DEX swap must not trigger flash loan detection.
///
/// A swap has exactly one incoming and one outgoing Transfer, but the
/// borrow/repay topology is absent — there is no flash loan provider callback.
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

/// Reentrancy pattern with CALL depth structure and SSTORE must be detected.
///
/// Validates the core reentrancy classifier (detect_reentrancy):
/// victim CALL → attacker → re-entry CALL → victim → SSTORE.
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

/// Reentrancy confidence must be at least medium (>= 0.7) when SSTORE is present.
#[test]
fn test_classifier_reentrancy_confidence_with_sstore() {
    let steps = reentrancy_with_sstore_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let reentrancy = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));
    assert!(
        reentrancy.is_some(),
        "Reentrancy must be detected; got: {detected:?}"
    );
    let confidence = reentrancy.unwrap().confidence;
    assert!(
        confidence >= 0.7,
        "Reentrancy with SSTORE confidence should be >= 0.7, got {confidence}"
    );
}

/// Balancer flash loan evidence chain must include ERC-20 token information.
///
/// When Strategy 2 matches (ERC-20 transfers), the pattern should record
/// the token address and provider (Balancer Vault).
#[test]
fn test_classifier_balancer_flash_loan_has_token_evidence() {
    let steps = balancer_flash_loan_fixture();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }));
    assert!(
        flash.is_some(),
        "Balancer flash loan must be detected; got: {detected:?}"
    );
    if let AttackPattern::FlashLoan { token, .. } = &flash.unwrap().pattern {
        // Strategy 2 (ERC-20) should populate token field
        assert!(
            token.is_some(),
            "ERC-20 flash loan must record token address; token was None"
        );
    }
}

/// Empty trace must produce no patterns (boundary condition).
#[test]
fn test_classifier_empty_trace_produces_no_patterns() {
    let steps: Vec<StepRecord> = vec![];
    let patterns = AttackClassifier::classify(&steps);
    assert!(
        patterns.is_empty(),
        "Empty trace must produce no patterns; got: {patterns:?}"
    );
}

/// Very short trace (< 4 steps) must not panic and produces no flash loan.
#[test]
fn test_classifier_short_trace_no_flash_loan() {
    let steps = vec![
        make_step(0, 0x60, 0, addr(0x1)), // PUSH1
        make_step(1, 0x60, 0, addr(0x1)), // PUSH1
        make_step(2, 0xF3, 0, addr(0x1)), // RETURN
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
