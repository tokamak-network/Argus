//! Tests for the Smart Contract Autopsy Lab.
//!
//! These tests use synthetic traces (no network calls required).

use bytes::Bytes;
use ethrex_common::{Address, H256, U256};

use crate::types::{ReplayConfig, ReplayTrace, StepRecord, StorageWrite};

use crate::autopsy::{
    classifier::AttackClassifier,
    enrichment::{collect_sstore_slots, enrich_storage_writes},
    fund_flow::FundFlowTracer,
    report::AutopsyReport,
    types::{AttackPattern, Severity},
};

// ============================================================
// Helpers to build synthetic StepRecords
// ============================================================

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
    }
}

fn make_call_step(
    index: usize,
    depth: usize,
    from: Address,
    to: Address,
    value: U256,
) -> StepRecord {
    // CALL: stack = [gas, to, value, ...]
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
    }
}

fn make_sstore_step(
    index: usize,
    depth: usize,
    address: Address,
    slot: H256,
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
            slot,
            old_value: U256::zero(),
            new_value,
        }]),
        log_topics: None,
        log_data: None,
    }
}

fn make_staticcall_step(index: usize, depth: usize, from: Address, to: Address) -> StepRecord {
    let to_u256 = U256::from_big_endian(to.as_bytes());
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0xFA, // STATICCALL
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![U256::from(100_000), to_u256],
        stack_depth: 6,
        memory_size: 0,
        code_address: from,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
    }
}

fn transfer_topic() -> H256 {
    // keccak256("Transfer(address,address,uint256)")
    // = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
    let mut bytes = [0u8; 32];
    bytes[0] = 0xdd;
    bytes[1] = 0xf2;
    bytes[2] = 0x52;
    bytes[3] = 0xad;
    H256::from(bytes)
}

fn make_log3_transfer(
    index: usize,
    depth: usize,
    token: Address,
    from: Address,
    to: Address,
) -> StepRecord {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(from.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(to.as_bytes());

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
            H256::from(from_bytes),
            H256::from(to_bytes),
        ]),
        log_data: None,
    }
}

fn make_log3_transfer_with_amount(
    index: usize,
    depth: usize,
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> StepRecord {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(from.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(to.as_bytes());

    // ABI-encode amount as uint256 (big-endian 32 bytes)
    let amount_data = amount.to_big_endian().to_vec();

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
            H256::from(from_bytes),
            H256::from(to_bytes),
        ]),
        log_data: Some(amount_data),
    }
}

fn make_caller_step(index: usize, depth: usize, address: Address) -> StepRecord {
    make_step_with_opcode(index, 0x33, depth, address) // CALLER
}

fn make_step_with_opcode(index: usize, opcode: u8, depth: usize, address: Address) -> StepRecord {
    make_step(index, opcode, depth, address)
}

/// Create an SLOAD step (pre-execution state has slot key on stack top).
fn make_sload_step(index: usize, depth: usize, address: Address, slot_key: U256) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0x54, // SLOAD
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![slot_key],
        stack_depth: 1,
        memory_size: 0,
        code_address: address,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
    }
}

/// Create a step following SLOAD with the return value at stack top.
fn make_post_sload_step(
    index: usize,
    depth: usize,
    address: Address,
    return_value: U256,
) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0x01, // ADD (arbitrary opcode after SLOAD)
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![return_value],
        stack_depth: 1,
        memory_size: 0,
        code_address: address,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
    }
}

fn addr(n: u64) -> Address {
    Address::from_low_u64_be(n)
}

fn slot(n: u64) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    H256::from(bytes)
}

// ============================================================
// RPC Client Parsing Tests (already inline in rpc_client.rs)
// ============================================================

// The rpc_client.rs has its own #[cfg(test)] module with 12 tests.
// Here we test the higher-level autopsy components.

// ============================================================
// Enrichment Tests
// ============================================================

#[test]
fn test_enrich_no_sstores() {
    let mut trace = ReplayTrace {
        steps: vec![make_step(0, 0x00, 0, addr(1))],
        config: ReplayConfig::default(),
        gas_used: 21000,
        success: true,
        output: Bytes::new(),
    };
    let initial = rustc_hash::FxHashMap::default();
    enrich_storage_writes(&mut trace, &initial);
    // No change — no SSTORE steps
    assert!(trace.steps[0].storage_writes.is_none());
}

#[test]
fn test_enrich_single_sstore_with_initial() {
    let contract = addr(0x42);
    let s = slot(1);
    let mut trace = ReplayTrace {
        steps: vec![make_sstore_step(0, 0, contract, s, U256::from(100))],
        config: ReplayConfig::default(),
        gas_used: 21000,
        success: true,
        output: Bytes::new(),
    };
    let mut initial = rustc_hash::FxHashMap::default();
    initial.insert((contract, s), U256::from(50));

    enrich_storage_writes(&mut trace, &initial);

    let write = &trace.steps[0].storage_writes.as_ref().unwrap()[0];
    assert_eq!(write.old_value, U256::from(50));
    assert_eq!(write.new_value, U256::from(100));
}

#[test]
fn test_enrich_chained_sstores() {
    let contract = addr(0x42);
    let s = slot(1);
    let mut trace = ReplayTrace {
        steps: vec![
            make_sstore_step(0, 0, contract, s, U256::from(10)),
            make_sstore_step(1, 0, contract, s, U256::from(20)),
            make_sstore_step(2, 0, contract, s, U256::from(30)),
        ],
        config: ReplayConfig::default(),
        gas_used: 21000,
        success: true,
        output: Bytes::new(),
    };
    let initial = rustc_hash::FxHashMap::default();
    enrich_storage_writes(&mut trace, &initial);

    let w0 = &trace.steps[0].storage_writes.as_ref().unwrap()[0];
    assert_eq!(w0.old_value, U256::zero()); // No initial, defaults to zero
    assert_eq!(w0.new_value, U256::from(10));

    let w1 = &trace.steps[1].storage_writes.as_ref().unwrap()[0];
    assert_eq!(w1.old_value, U256::from(10)); // Previous write's new_value
    assert_eq!(w1.new_value, U256::from(20));

    let w2 = &trace.steps[2].storage_writes.as_ref().unwrap()[0];
    assert_eq!(w2.old_value, U256::from(20));
    assert_eq!(w2.new_value, U256::from(30));
}

#[test]
fn test_collect_sstore_slots_deduplicates() {
    let contract = addr(0x42);
    let s = slot(1);
    let steps = vec![
        make_sstore_step(0, 0, contract, s, U256::from(10)),
        make_sstore_step(1, 0, contract, s, U256::from(20)),
        make_sstore_step(2, 0, contract, slot(2), U256::from(30)),
    ];
    let slots = collect_sstore_slots(&steps);
    assert_eq!(slots.len(), 2); // slot(1) deduplicated
}

// ============================================================
// Classifier Tests
// ============================================================

#[test]
fn test_classify_empty_trace() {
    let patterns = AttackClassifier::classify(&[]);
    assert!(patterns.is_empty());
}

#[test]
fn test_classify_no_attacks() {
    let steps = vec![
        make_step(0, 0x60, 0, addr(1)), // PUSH1
        make_step(1, 0x01, 0, addr(1)), // ADD
        make_step(2, 0x00, 0, addr(1)), // STOP
    ];
    let patterns = AttackClassifier::classify(&steps);
    assert!(patterns.is_empty());
}

#[test]
fn test_detect_reentrancy() {
    let victim = addr(0x42);
    let attacker = addr(0x99);

    let steps = vec![
        // Victim calls attacker at depth 0
        make_call_step(0, 0, victim, attacker, U256::zero()),
        // Attacker executes at depth 1
        make_step(1, 0x60, 1, attacker),
        // Attacker re-enters victim via CALL at depth 1
        make_call_step(2, 1, attacker, victim, U256::zero()),
        // Victim executes at depth 2
        make_step(3, 0x60, 2, victim),
        // Victim does SSTORE during re-entry
        make_sstore_step(4, 2, victim, slot(1), U256::from(999)),
    ];

    let patterns = AttackClassifier::classify(&steps);
    assert!(!patterns.is_empty());
    assert!(matches!(patterns[0], AttackPattern::Reentrancy { .. }));
}

#[test]
fn test_detect_flash_loan_eth() {
    let lender = addr(0x10);
    let borrower = addr(0x20);

    // Total 100 steps, borrow in first quarter, repay in last quarter
    let mut steps: Vec<StepRecord> = Vec::new();

    // Step 0: Large borrow (first quarter of 100 = step 0..25)
    steps.push(make_call_step(
        0,
        0,
        lender,
        borrower,
        U256::from(1_000_000),
    ));

    // Fill middle with NOPs
    for i in 1..80 {
        steps.push(make_step(i, 0x00, 0, borrower));
    }

    // Step 80: Repay in last quarter (75..100)
    steps.push(make_call_step(
        80,
        0,
        borrower,
        lender,
        U256::from(1_000_100),
    ));

    // Fill rest
    for i in 81..100 {
        steps.push(make_step(i, 0x00, 0, borrower));
    }

    let patterns = AttackClassifier::classify(&steps);
    let flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();
    assert!(!flash_loans.is_empty());
    // ETH flash loan: no provider/token
    if let AttackPattern::FlashLoan {
        provider, token, ..
    } = &flash_loans[0]
    {
        assert!(provider.is_none());
        assert!(token.is_none());
    }
}

#[test]
fn test_detect_flash_loan_erc20() {
    let token_addr = addr(0xDEAD);
    let lender_pool = addr(0x10);
    let borrower = addr(0x20);

    let mut steps: Vec<StepRecord> = Vec::new();

    // Step 0: ERC-20 Transfer from lender → borrower (borrow)
    steps.push(make_log3_transfer(0, 0, token_addr, lender_pool, borrower));

    // Fill with ops in the middle (total ~100 steps)
    for i in 1..80 {
        steps.push(make_step(i, 0x01, 0, borrower)); // ADD ops
    }

    // Step 80: ERC-20 Transfer from borrower → lender (repay)
    steps.push(make_log3_transfer(80, 0, token_addr, borrower, lender_pool));

    for i in 81..100 {
        steps.push(make_step(i, 0x00, 0, borrower));
    }

    let patterns = AttackClassifier::classify(&steps);
    let flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();
    assert!(!flash_loans.is_empty(), "should detect ERC-20 flash loan");
    if let AttackPattern::FlashLoan {
        token, provider, ..
    } = &flash_loans[0]
    {
        assert_eq!(*token, Some(token_addr));
        assert_eq!(*provider, Some(lender_pool));
    }
}

#[test]
fn test_detect_flash_loan_callback() {
    let attacker = addr(0x99);
    let flash_provider = addr(0xAA);

    // Simulate: attacker (depth 0) → flash provider (depth 1) → callback to
    // attacker (depth 2+) where most execution happens.
    let mut steps: Vec<StepRecord> = Vec::new();

    // Entry: attacker calls flash provider at depth 0
    steps.push(make_call_step(0, 0, attacker, flash_provider, U256::zero()));

    // Flash provider calls back at depth 1
    steps.push(make_call_step(1, 1, flash_provider, attacker, U256::zero()));

    // 90% of execution at depth 2+ (inside callback)
    for i in 2..92 {
        steps.push(make_step(i, 0x01, 2, attacker)); // ADD ops at depth 2
    }

    // SSTORE inside the callback (state modification = non-trivial)
    steps.push(make_sstore_step(92, 2, attacker, slot(1), U256::from(42)));

    // CALL inside callback
    steps.push(make_call_step(93, 2, attacker, addr(0xBB), U256::zero()));

    // More ops at depth 2
    for i in 94..98 {
        steps.push(make_step(i, 0x01, 2, attacker));
    }

    // Return to depth 0
    steps.push(make_step(98, 0xF3, 1, flash_provider)); // RETURN
    steps.push(make_step(99, 0x00, 0, attacker)); // STOP

    let patterns = AttackClassifier::classify(&steps);
    let flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();
    assert!(
        !flash_loans.is_empty(),
        "should detect callback-based flash loan"
    );
    if let AttackPattern::FlashLoan { provider, .. } = &flash_loans[0] {
        assert_eq!(*provider, Some(flash_provider));
    }
}

#[test]
fn test_no_flash_loan_for_shallow_execution() {
    let contract = addr(0x42);

    // All execution at depth 0 — no callback pattern
    let mut steps: Vec<StepRecord> = Vec::new();
    for i in 0..100 {
        steps.push(make_step(i, 0x01, 0, contract));
    }

    let patterns = AttackClassifier::classify(&steps);
    let flash_loans: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::FlashLoan { .. }))
        .collect();
    assert!(
        flash_loans.is_empty(),
        "shallow execution should not trigger flash loan"
    );
}

#[test]
fn test_detect_price_manipulation() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim_contract = addr(0x42);

    let steps = vec![
        // Read oracle price
        make_staticcall_step(0, 0, victim_contract, oracle),
        // Swap on DEX (LOG3 Transfer)
        make_log3_transfer(1, 0, dex, addr(0xA), addr(0xB)),
        // Read oracle price again
        make_staticcall_step(2, 0, victim_contract, oracle),
    ];

    let patterns = AttackClassifier::classify(&steps);
    let price_manip: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::PriceManipulation { .. }))
        .collect();
    assert!(!price_manip.is_empty());
    // No SLOAD data → delta should be -1.0 (unknown)
    if let AttackPattern::PriceManipulation {
        price_delta_percent,
        ..
    } = price_manip[0]
    {
        assert!(
            *price_delta_percent < 0.0,
            "without SLOAD data, delta should be -1.0 (unknown)"
        );
    }
}

// ============================================================
// Phase II-2: Price Delta Calculation
// ============================================================

#[test]
fn test_price_delta_with_known_oracle_values() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim = addr(0x42);
    let slot_key = U256::from(1); // Oracle storage slot

    let steps = vec![
        // STATICCALL to oracle (read 1)
        make_staticcall_step(0, 0, victim, oracle),
        // SLOAD in oracle contract — slot 1, value 100
        make_sload_step(1, 1, oracle, slot_key),
        make_post_sload_step(2, 1, oracle, U256::from(100)),
        // Swap on DEX
        make_log3_transfer(3, 0, dex, addr(0xA), addr(0xB)),
        // STATICCALL to oracle (read 2)
        make_staticcall_step(4, 0, victim, oracle),
        // SLOAD in oracle contract — same slot, value 150
        make_sload_step(5, 1, oracle, slot_key),
        make_post_sload_step(6, 1, oracle, U256::from(150)),
    ];

    let patterns = AttackClassifier::classify(&steps);
    let price_manip: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::PriceManipulation { .. }))
        .collect();
    assert!(!price_manip.is_empty(), "should detect price manipulation");
    if let AttackPattern::PriceManipulation {
        price_delta_percent,
        ..
    } = price_manip[0]
    {
        // |150 - 100| / 100 * 100 = 50%
        assert!(
            (*price_delta_percent - 50.0).abs() < 0.1,
            "price delta should be ~50%, got {price_delta_percent}"
        );
    }
}

#[test]
fn test_price_delta_same_value_reads_zero() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim = addr(0x42);
    let slot_key = U256::from(1);

    let steps = vec![
        make_staticcall_step(0, 0, victim, oracle),
        make_sload_step(1, 1, oracle, slot_key),
        make_post_sload_step(2, 1, oracle, U256::from(200)),
        make_log3_transfer(3, 0, dex, addr(0xA), addr(0xB)),
        make_staticcall_step(4, 0, victim, oracle),
        make_sload_step(5, 1, oracle, slot_key),
        make_post_sload_step(6, 1, oracle, U256::from(200)), // Same value
    ];

    let patterns = AttackClassifier::classify(&steps);
    let price_manip: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::PriceManipulation { .. }))
        .collect();
    assert!(!price_manip.is_empty());
    if let AttackPattern::PriceManipulation {
        price_delta_percent,
        ..
    } = price_manip[0]
    {
        assert!(
            (*price_delta_percent).abs() < 0.01,
            "same-value reads should yield 0% delta, got {price_delta_percent}"
        );
    }
}

#[test]
fn test_price_delta_unknown_no_sload() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim = addr(0x42);

    // No SLOAD steps — only STATICCALL + Transfer
    let steps = vec![
        make_staticcall_step(0, 0, victim, oracle),
        make_log3_transfer(1, 0, dex, addr(0xA), addr(0xB)),
        make_staticcall_step(2, 0, victim, oracle),
    ];

    let patterns = AttackClassifier::classify(&steps);
    let price_manip: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::PriceManipulation { .. }))
        .collect();
    assert!(!price_manip.is_empty());
    if let AttackPattern::PriceManipulation {
        price_delta_percent,
        ..
    } = price_manip[0]
    {
        assert!(
            *price_delta_percent < 0.0,
            "no SLOAD data → delta should be -1.0, got {price_delta_percent}"
        );
    }
}

#[test]
fn test_price_delta_report_displays_percentage() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim = addr(0x42);
    let slot_key = U256::from(1);

    let steps = vec![
        make_staticcall_step(0, 0, victim, oracle),
        make_sload_step(1, 1, oracle, slot_key),
        make_post_sload_step(2, 1, oracle, U256::from(100)),
        make_log3_transfer(3, 0, dex, addr(0xA), addr(0xB)),
        make_staticcall_step(4, 0, victim, oracle),
        make_sload_step(5, 1, oracle, slot_key),
        make_post_sload_step(6, 1, oracle, U256::from(120)),
    ];

    let patterns = AttackClassifier::classify(&steps);
    let report = AutopsyReport::build(H256::zero(), 12345, &steps, patterns, vec![], vec![]);
    let md = report.to_markdown();

    // 20% delta
    assert!(
        md.contains("20.0%"),
        "report should display price delta percentage, got:\n{md}"
    );
    assert!(
        !md.contains("unknown"),
        "report should show actual percentage, not unknown"
    );
}

#[test]
fn test_detect_access_control_bypass() {
    let contract = addr(0x42);

    let steps = vec![
        // SSTORE without any CALLER check
        make_sstore_step(0, 0, contract, slot(1), U256::from(1)),
    ];

    let patterns = AttackClassifier::classify(&steps);
    let bypasses: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::AccessControlBypass { .. }))
        .collect();
    assert!(!bypasses.is_empty());
}

#[test]
fn test_no_access_control_bypass_with_caller_check() {
    let contract = addr(0x42);

    let steps = vec![
        make_caller_step(0, 0, contract),                         // CALLER
        make_sstore_step(1, 0, contract, slot(1), U256::from(1)), // SSTORE
    ];

    let patterns = AttackClassifier::classify(&steps);
    let bypasses: Vec<_> = patterns
        .iter()
        .filter(|p| matches!(p, AttackPattern::AccessControlBypass { .. }))
        .collect();
    assert!(bypasses.is_empty()); // CALLER check present → no bypass
}

// ============================================================
// Fund Flow Tests
// ============================================================

#[test]
fn test_trace_empty() {
    let flows = FundFlowTracer::trace(&[]);
    assert!(flows.is_empty());
}

#[test]
fn test_trace_eth_transfer() {
    let from = addr(0x42);
    let to = addr(0x99);

    let steps = vec![make_call_step(0, 0, from, to, U256::from(1_000_000))];

    let flows = FundFlowTracer::trace(&steps);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].from, from);
    assert_eq!(flows[0].to, to);
    assert_eq!(flows[0].value, U256::from(1_000_000));
    assert!(flows[0].token.is_none()); // ETH transfer
}

#[test]
fn test_trace_zero_value_call_excluded() {
    let steps = vec![make_call_step(0, 0, addr(1), addr(2), U256::zero())];
    let flows = FundFlowTracer::trace(&steps);
    assert!(flows.is_empty()); // Zero-value calls are not fund flows
}

#[test]
fn test_trace_erc20_transfer() {
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);

    let steps = vec![make_log3_transfer(0, 0, token, from, to)];

    let flows = FundFlowTracer::trace(&steps);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].from, from);
    assert_eq!(flows[0].to, to);
    assert_eq!(flows[0].token, Some(token));
}

#[test]
fn test_trace_mixed_eth_and_erc20() {
    let steps = vec![
        make_call_step(0, 0, addr(1), addr(2), U256::from(500)),
        make_log3_transfer(1, 0, addr(0xDEAD), addr(3), addr(4)),
    ];

    let flows = FundFlowTracer::trace(&steps);
    assert_eq!(flows.len(), 2);
    // Should be sorted by step_index
    assert!(flows[0].token.is_none()); // ETH first
    assert!(flows[1].token.is_some()); // ERC-20 second
}

// ============================================================
// Report Tests
// ============================================================

#[test]
fn test_report_empty() {
    let report = AutopsyReport::build(H256::zero(), 12345, &[], vec![], vec![], vec![]);
    assert_eq!(report.total_steps, 0);
    assert!(report.attack_patterns.is_empty());
    assert!(report.fund_flows.is_empty());
    assert!(report.key_steps.is_empty());
    assert!(report.suggested_fixes.is_empty());
    assert!(report.summary.contains("No known attack patterns detected"));
}

#[test]
fn test_report_with_reentrancy() {
    let patterns = vec![AttackPattern::Reentrancy {
        target_contract: addr(0x42),
        reentrant_call_step: 10,
        state_modified_step: 15,
        call_depth_at_entry: 1,
    }];

    let report = AutopsyReport::build(H256::zero(), 100, &[], patterns, vec![], vec![]);

    assert_eq!(report.attack_patterns.len(), 1);
    assert!(report.summary.contains("Reentrancy"));
    assert!(!report.suggested_fixes.is_empty());
    assert!(
        report
            .suggested_fixes
            .iter()
            .any(|f| f.contains("ReentrancyGuard"))
    );
}

#[test]
fn test_report_json_roundtrip() {
    let report = AutopsyReport::build(H256::zero(), 100, &[], vec![], vec![], vec![]);
    let json = report.to_json().expect("should serialize");
    assert!(json.contains("\"block_number\""));
    assert!(json.contains("\"total_steps\""));
    assert!(json.contains("\"summary\""));
}

#[test]
fn test_report_markdown_sections() {
    let patterns = vec![AttackPattern::AccessControlBypass {
        sstore_step: 5,
        contract: addr(0x42),
    }];

    let flows = vec![super::super::autopsy::types::FundFlow {
        from: addr(1),
        to: addr(2),
        value: U256::from(100),
        token: None,
        step_index: 3,
    }];

    let diffs = vec![StorageWrite {
        address: addr(0x42),
        slot: slot(1),
        old_value: U256::from(0),
        new_value: U256::from(1),
    }];

    let report = AutopsyReport::build(H256::zero(), 100, &[], patterns, flows, diffs);
    let md = report.to_markdown();

    assert!(md.contains("# Smart Contract Autopsy Report"));
    assert!(md.contains("## Attack Patterns"));
    assert!(md.contains("## Fund Flow"));
    assert!(md.contains("## Storage Changes"));
    assert!(md.contains("## Key Steps"));
    assert!(md.contains("## Suggested Fixes"));
    assert!(md.contains("## Conclusion"));
}

#[test]
fn test_report_key_steps_sorted() {
    let patterns = vec![
        AttackPattern::Reentrancy {
            target_contract: addr(0x42),
            reentrant_call_step: 20,
            state_modified_step: 30,
            call_depth_at_entry: 1,
        },
        AttackPattern::AccessControlBypass {
            sstore_step: 5,
            contract: addr(0x42),
        },
    ];

    let report = AutopsyReport::build(H256::zero(), 100, &[], patterns, vec![], vec![]);

    // Key steps should be sorted by step_index
    let indices: Vec<usize> = report.key_steps.iter().map(|s| s.step_index).collect();
    for i in 1..indices.len() {
        assert!(indices[i] >= indices[i - 1], "key_steps not sorted");
    }
}

#[test]
fn test_report_affected_contracts_deduped() {
    let flows = vec![
        super::super::autopsy::types::FundFlow {
            from: addr(1),
            to: addr(2),
            value: U256::from(100),
            token: None,
            step_index: 0,
        },
        super::super::autopsy::types::FundFlow {
            from: addr(1),
            to: addr(3),
            value: U256::from(200),
            token: None,
            step_index: 1,
        },
    ];

    let report = AutopsyReport::build(H256::zero(), 100, &[], vec![], flows, vec![]);

    // addr(1) should appear only once
    let count = report
        .affected_contracts
        .iter()
        .filter(|&&a| a == addr(1))
        .count();
    assert_eq!(count, 1);
}

#[test]
fn test_report_severity_levels() {
    let patterns = vec![AttackPattern::Reentrancy {
        target_contract: addr(0x42),
        reentrant_call_step: 10,
        state_modified_step: 15,
        call_depth_at_entry: 1,
    }];

    let report = AutopsyReport::build(H256::zero(), 100, &[], patterns, vec![], vec![]);

    assert!(
        report
            .key_steps
            .iter()
            .any(|s| s.severity == Severity::Critical)
    );
}

// ============================================================
// StepRecord New Fields Tests
// ============================================================

#[test]
fn test_step_record_none_fields_skip_serializing() {
    let step = StepRecord {
        step_index: 0,
        pc: 0,
        opcode: 0x00,
        depth: 0,
        gas_remaining: 21000,
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address: Address::zero(),
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
    };
    let json = serde_json::to_string(&step).unwrap();
    assert!(!json.contains("call_value"));
    assert!(!json.contains("storage_writes"));
    assert!(!json.contains("log_topics"));
    assert!(!json.contains("log_data"));
}

#[test]
fn test_step_record_some_fields_serialize() {
    let step = StepRecord {
        step_index: 0,
        pc: 0,
        opcode: 0xF1,
        depth: 0,
        gas_remaining: 21000,
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address: Address::zero(),
        call_value: Some(U256::from(1000)),
        storage_writes: None,
        log_topics: None,
        log_data: None,
    };
    let json = serde_json::to_string(&step).unwrap();
    assert!(json.contains("call_value"));
    assert!(!json.contains("storage_writes"));
    assert!(!json.contains("log_topics"));
}

// ============================================================
// Integration: Recorder enrichment of CALL/LOG/SSTORE
// ============================================================

#[test]
fn test_recorder_captures_call_value() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let memory = Memory::new();

    // CALL stack: gas, to, value, ...
    stack.push(U256::from(0)).unwrap(); // retSize
    stack.push(U256::from(0)).unwrap(); // retOffset
    stack.push(U256::from(0)).unwrap(); // argsSize
    stack.push(U256::from(0)).unwrap(); // argsOffset
    stack.push(U256::from(5000)).unwrap(); // value
    stack.push(U256::from(0x99)).unwrap(); // to
    stack.push(U256::from(100_000)).unwrap(); // gas

    recorder.record_step(0xF1, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    assert_eq!(recorder.steps.len(), 1);
    assert_eq!(recorder.steps[0].call_value, Some(U256::from(5000)));
}

#[test]
fn test_recorder_captures_log_topics() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let memory = Memory::new();

    let topic = U256::from(0xDEADBEEF_u64);
    // LOG1 stack: offset, size, topic0
    stack.push(topic).unwrap(); // topic0
    stack.push(U256::from(32)).unwrap(); // size
    stack.push(U256::from(0)).unwrap(); // offset

    recorder.record_step(0xA1, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    assert_eq!(recorder.steps.len(), 1);
    let topics = recorder.steps[0].log_topics.as_ref().unwrap();
    assert_eq!(topics.len(), 1);
}

#[test]
fn test_recorder_captures_sstore() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let memory = Memory::new();

    // SSTORE stack: key, value
    stack.push(U256::from(42)).unwrap(); // value
    stack.push(U256::from(1)).unwrap(); // key

    recorder.record_step(0x55, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    assert_eq!(recorder.steps.len(), 1);
    let writes = recorder.steps[0].storage_writes.as_ref().unwrap();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].address, addr(0x42));
    assert_eq!(writes[0].new_value, U256::from(42));
    assert_eq!(writes[0].old_value, U256::zero()); // Not enriched yet
}

#[test]
fn test_recorder_non_special_opcode_has_no_extras() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let stack = Stack::default();
    let memory = Memory::new();

    recorder.record_step(0x01, 0, 1_000_000, 0, &stack, &memory, addr(0x42)); // ADD

    assert!(recorder.steps[0].call_value.is_none());
    assert!(recorder.steps[0].storage_writes.is_none());
    assert!(recorder.steps[0].log_topics.is_none());
    assert!(recorder.steps[0].log_data.is_none());
}

// ============================================================
// Phase II-1: ERC-20 Transfer Amount Capture
// ============================================================

#[test]
fn test_recorder_captures_log3_data_from_memory() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let mut memory = Memory::new();

    // Write 32 bytes of amount data at offset 0
    let amount = U256::from(1_000_000u64);
    let amount_bytes = amount.to_big_endian();
    memory.store_data(0, &amount_bytes).unwrap();

    // LOG3 stack: offset, size, topic0, topic1, topic2
    let topic = U256::from(0xDEADBEEF_u64);
    stack.push(topic).unwrap(); // topic2
    stack.push(topic).unwrap(); // topic1
    stack.push(topic).unwrap(); // topic0
    stack.push(U256::from(32)).unwrap(); // size
    stack.push(U256::from(0)).unwrap(); // offset

    recorder.record_step(0xA3, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    assert_eq!(recorder.steps.len(), 1);
    let log_data = recorder.steps[0].log_data.as_ref().unwrap();
    assert_eq!(log_data.len(), 32);
    // Verify we can decode the amount back
    let decoded = U256::from_big_endian(log_data);
    assert_eq!(decoded, amount);
}

#[test]
fn test_erc20_amount_decoding_in_fund_flow() {
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);
    let amount = U256::from(5_000_000u64);

    let steps = vec![make_log3_transfer_with_amount(
        0, 0, token, from, to, amount,
    )];

    let flows = FundFlowTracer::trace(&steps);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].from, from);
    assert_eq!(flows[0].to, to);
    assert_eq!(flows[0].token, Some(token));
    assert_eq!(
        flows[0].value, amount,
        "ERC-20 amount should be decoded from log_data"
    );
}

#[test]
fn test_log_data_cap_enforcement() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let mut memory = Memory::new();

    // Write 512 bytes of data at offset 0
    let big_data = vec![0xAB; 512];
    memory.store_data(0, &big_data).unwrap();

    // LOG0 stack: offset, size
    stack.push(U256::from(512)).unwrap(); // size (over 256 cap)
    stack.push(U256::from(0)).unwrap(); // offset

    recorder.record_step(0xA0, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    let log_data = recorder.steps[0].log_data.as_ref().unwrap();
    assert_eq!(
        log_data.len(),
        256,
        "LOG data should be capped at 256 bytes"
    );
    assert!(log_data.iter().all(|&b| b == 0xAB));
}

#[test]
fn test_fund_flow_without_log_data_shows_zero() {
    // Backward compat: old StepRecords without log_data should have value=0
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);

    // Use old-style helper (no log_data)
    let steps = vec![make_log3_transfer(0, 0, token, from, to)];

    let flows = FundFlowTracer::trace(&steps);
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].value,
        U256::zero(),
        "missing log_data should yield zero value"
    );
}

#[test]
fn test_report_displays_decoded_erc20_amount() {
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);
    let amount = U256::from(42_000u64);

    let steps = vec![make_log3_transfer_with_amount(
        0, 0, token, from, to, amount,
    )];
    let flows = FundFlowTracer::trace(&steps);

    let report = AutopsyReport::build(H256::zero(), 12345, &steps, vec![], flows, vec![]);
    let md = report.to_markdown();

    assert!(
        md.contains("42000"),
        "Markdown report should contain decoded amount"
    );
    assert!(
        !md.contains("(undecoded)"),
        "Should not show (undecoded) when amount is decoded"
    );
}

#[test]
fn test_recorder_log0_captures_data_no_topics() {
    use crate::recorder::DebugRecorder;
    use crate::types::ReplayConfig;
    use ethrex_levm::call_frame::Stack;
    use ethrex_levm::debugger_hook::OpcodeRecorder;
    use ethrex_levm::memory::Memory;

    let mut recorder = DebugRecorder::new(ReplayConfig::default());
    let mut stack = Stack::default();
    let mut memory = Memory::new();

    // Write some data at offset 0
    memory.store_data(0, &[1, 2, 3, 4]).unwrap();

    // LOG0 stack: offset, size (no topics)
    stack.push(U256::from(4)).unwrap(); // size
    stack.push(U256::from(0)).unwrap(); // offset

    recorder.record_step(0xA0, 0, 1_000_000, 0, &stack, &memory, addr(0x42));

    let step = &recorder.steps[0];
    // LOG0 has no topics
    let topics = step.log_topics.as_ref().unwrap();
    assert!(topics.is_empty());
    // But data should be captured
    let data = step.log_data.as_ref().unwrap();
    assert_eq!(data, &[1, 2, 3, 4]);
}

// ============================================================
// Phase II-4: ABI-Based Storage Slot Decoding
// ============================================================

#[test]
fn test_abi_simple_variable_slot() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    let layout = r#"[
        { "name": "owner", "slot": 0, "type": "address" },
        { "name": "totalSupply", "slot": 1, "type": "uint256" }
    ]"#;
    let decoder = AbiDecoder::from_storage_layout_json(layout).unwrap();

    // Slot 0 → "owner"
    let slot0 = H256::from_low_u64_be(0);
    let label = decoder.label_slot(&slot0).unwrap();
    assert_eq!(label.name, "owner");
    assert!(label.key.is_none());

    // Slot 1 → "totalSupply"
    let slot1 = H256::from_low_u64_be(1);
    let label = decoder.label_slot(&slot1).unwrap();
    assert_eq!(label.name, "totalSupply");
}

#[test]
fn test_abi_mapping_slot_address_key() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    // balances mapping at slot 1, key = address 0x42
    let key_addr = Address::from_low_u64_be(0x42);
    let mut key_bytes = [0u8; 20];
    key_bytes.copy_from_slice(key_addr.as_bytes());

    let computed = AbiDecoder::mapping_slot(&key_bytes, 1);
    // Verify it's a 32-byte hash (non-zero)
    assert_ne!(computed, H256::zero());

    // Verify deterministic
    let computed2 = AbiDecoder::mapping_slot(&key_bytes, 1);
    assert_eq!(computed, computed2);

    // Different key → different slot
    let key2 = Address::from_low_u64_be(0x43);
    let mut key2_bytes = [0u8; 20];
    key2_bytes.copy_from_slice(key2.as_bytes());
    let computed3 = AbiDecoder::mapping_slot(&key2_bytes, 1);
    assert_ne!(computed, computed3);
}

#[test]
fn test_abi_mapping_slot_u256_key() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    let key = U256::from(42);
    let slot = AbiDecoder::mapping_slot_u256(key, 3);
    assert_ne!(slot, H256::zero());

    // Same key, different position → different slot
    let slot2 = AbiDecoder::mapping_slot_u256(key, 4);
    assert_ne!(slot, slot2);
}

#[test]
fn test_abi_json_parsing() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    // Valid layout
    let layout = r#"[{ "name": "x", "slot": 0, "type": "uint256" }]"#;
    assert!(AbiDecoder::from_storage_layout_json(layout).is_ok());

    // Invalid JSON
    assert!(AbiDecoder::from_storage_layout_json("not json").is_err());

    // Missing name field
    let bad = r#"[{ "slot": 0, "type": "uint256" }]"#;
    assert!(AbiDecoder::from_storage_layout_json(bad).is_err());

    // Missing slot field
    let bad2 = r#"[{ "name": "x", "type": "uint256" }]"#;
    assert!(AbiDecoder::from_storage_layout_json(bad2).is_err());
}

#[test]
fn test_abi_mapping_slot_lookup() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    let layout = r#"[
        { "name": "owner", "slot": 0, "type": "address" },
        { "name": "balances", "slot": 1, "type": "mapping(address => uint256)" }
    ]"#;
    let decoder = AbiDecoder::from_storage_layout_json(layout).unwrap();

    let key_addr = Address::from_low_u64_be(0x42);
    let mut key_bytes = [0u8; 20];
    key_bytes.copy_from_slice(key_addr.as_bytes());

    // Compute expected slot
    let expected_slot = AbiDecoder::mapping_slot(&key_bytes, 1);

    // Lookup with known keys
    let label = decoder
        .label_mapping_slot(&expected_slot, &[key_bytes])
        .unwrap();
    assert_eq!(label.name, "balances");
    assert!(label.key.is_some());
}

#[test]
fn test_abi_unknown_slot_returns_none() {
    use crate::autopsy::abi_decoder::AbiDecoder;

    let layout = r#"[{ "name": "x", "slot": 0, "type": "uint256" }]"#;
    let decoder = AbiDecoder::from_storage_layout_json(layout).unwrap();

    // Random slot not matching any variable
    let random = H256::from_low_u64_be(999);
    assert!(decoder.label_slot(&random).is_none());
}

// ============================================================
// Phase IV-1: Classifier Confidence Scoring
// ============================================================

#[test]
fn test_confidence_reentrancy_high() {
    // Re-entry + SSTORE + value transfer → high confidence
    let victim = addr(0x42);
    let attacker = addr(0x99);

    let steps = vec![
        // Victim calls attacker at depth 0
        make_call_step(0, 0, victim, attacker, U256::from(0)),
        // Attacker re-enters victim (CALL target = victim) at depth 1
        make_call_step(1, 1, attacker, victim, U256::from(1000)),
        // Victim state modified during re-entry
        make_sstore_step(2, 2, victim, slot(1), U256::from(42)),
    ];

    let detected = AttackClassifier::classify_with_confidence(&steps);
    let reentrancy: Vec<_> = detected
        .iter()
        .filter(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }))
        .collect();

    assert!(!reentrancy.is_empty(), "should detect reentrancy");
    assert!(
        reentrancy[0].confidence >= 0.7,
        "reentrancy with SSTORE should have high confidence, got {}",
        reentrancy[0].confidence
    );
    assert!(
        !reentrancy[0].evidence.is_empty(),
        "should have evidence strings"
    );
}

#[test]
fn test_confidence_access_control_medium() {
    let contract = addr(0x42);

    let steps = vec![make_sstore_step(0, 0, contract, slot(1), U256::from(1))];

    let detected = AttackClassifier::classify_with_confidence(&steps);
    let bypasses: Vec<_> = detected
        .iter()
        .filter(|d| matches!(d.pattern, AttackPattern::AccessControlBypass { .. }))
        .collect();

    assert!(!bypasses.is_empty());
    assert!(
        bypasses[0].confidence <= 0.6,
        "access control bypass is heuristic, should be medium confidence, got {}",
        bypasses[0].confidence
    );
}

#[test]
fn test_confidence_price_manip_with_delta() {
    let oracle = addr(0x50);
    let dex = addr(0x60);
    let victim = addr(0x42);
    let slot_key = U256::from(1);

    let steps = vec![
        make_staticcall_step(0, 0, victim, oracle),
        make_sload_step(1, 1, oracle, slot_key),
        make_post_sload_step(2, 1, oracle, U256::from(100)),
        make_log3_transfer(3, 0, dex, addr(0xA), addr(0xB)),
        make_staticcall_step(4, 0, victim, oracle),
        make_sload_step(5, 1, oracle, slot_key),
        make_post_sload_step(6, 1, oracle, U256::from(200)), // 100% delta
    ];

    let detected = AttackClassifier::classify_with_confidence(&steps);
    let price_manip: Vec<_> = detected
        .iter()
        .filter(|d| matches!(d.pattern, AttackPattern::PriceManipulation { .. }))
        .collect();

    assert!(!price_manip.is_empty());
    assert!(
        price_manip[0].confidence >= 0.8,
        "price manip with >5% delta should be high confidence, got {}",
        price_manip[0].confidence
    );
    assert!(
        price_manip[0].evidence.iter().any(|e| e.contains("delta")),
        "evidence should include price delta info"
    );
}

#[test]
fn test_confidence_flash_loan_partial_low() {
    let contract = addr(0x42);

    // Very shallow execution — no callback pattern, just depth 0 ops
    let mut steps: Vec<StepRecord> = Vec::new();
    for i in 0..100 {
        steps.push(make_step(i, 0x01, 0, contract));
    }

    let detected = AttackClassifier::classify_with_confidence(&steps);
    let flash_loans: Vec<_> = detected
        .iter()
        .filter(|d| matches!(d.pattern, AttackPattern::FlashLoan { .. }))
        .collect();

    // Should NOT detect flash loan in shallow execution
    assert!(
        flash_loans.is_empty(),
        "shallow execution should not trigger flash loan"
    );
}

#[test]
fn test_confidence_in_json_output() {
    let contract = addr(0x42);
    let steps = vec![make_sstore_step(0, 0, contract, slot(1), U256::from(1))];

    let detected = AttackClassifier::classify_with_confidence(&steps);
    assert!(!detected.is_empty());

    let json = serde_json::to_string(&detected[0]).unwrap();
    assert!(
        json.contains("confidence"),
        "JSON should include confidence field"
    );
    assert!(
        json.contains("evidence"),
        "JSON should include evidence field"
    );
}

#[test]
fn test_multiple_patterns_different_confidences() {
    let victim = addr(0x42);
    let attacker = addr(0x99);

    let mut steps = vec![
        // SSTORE without CALLER → access control bypass (medium)
        make_sstore_step(0, 0, victim, slot(1), U256::from(1)),
        // Victim calls attacker
        make_call_step(1, 0, victim, attacker, U256::from(0)),
        // Attacker re-enters victim
        make_call_step(2, 1, attacker, victim, U256::from(0)),
        // SSTORE during re-entry
        make_sstore_step(3, 2, victim, slot(2), U256::from(2)),
    ];
    // Pad with filler to avoid edge cases
    for i in 4..10 {
        steps.push(make_step(i, 0x01, 0, victim));
    }

    let detected = AttackClassifier::classify_with_confidence(&steps);
    assert!(detected.len() >= 2, "should detect multiple patterns");

    // Different patterns should have different confidences
    let confidences: Vec<f64> = detected.iter().map(|d| d.confidence).collect();
    let has_variety = confidences.windows(2).any(|w| (w[0] - w[1]).abs() > 0.01);
    assert!(
        has_variety || detected.len() == 1,
        "different patterns should have different confidence levels"
    );
}
