//! Tests for receipt-based fallback when LEVM diverges from on-chain result.
//!
//! Covers: Transfer log parsing, success_override precedence, DataQuality
//! branching, and receipt_fund_flows priority over opcode-traced flows.
//!
//! All tests are offline — no RPC calls.

use bytes::Bytes;
use ethrex_common::{Address, H256, U256};

use crate::autopsy::fund_flow::FundFlowTracer;
use crate::autopsy::rpc_client::RpcLog;
use crate::autopsy::types::FundFlow;
use crate::types::{DataQuality, EventType, ReplayConfig, ReplayTrace, StepRecord};

// ============================================================
// Helpers
// ============================================================

fn addr(n: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&n.to_be_bytes());
    Address::from_slice(&bytes)
}

/// Build a Transfer event topic (keccak256 of "Transfer(address,address,uint256)").
fn transfer_topic() -> H256 {
    H256([
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ])
}

/// Encode an address into a 32-byte left-padded topic.
fn address_to_topic(a: Address) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(a.as_bytes());
    H256::from(bytes)
}

/// Build a LOG3 Transfer step with amount encoded in log_data.
fn make_transfer_step(
    index: usize,
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> StepRecord {
    let amount_data = amount.to_big_endian().to_vec();

    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode: 0xA3, // LOG3
        depth: 0,
        gas_remaining: 1_000_000,
        stack_top: vec![],
        stack_depth: 5,
        memory_size: 64,
        code_address: token,
        call_value: None,
        storage_writes: None,
        log_topics: Some(vec![
            transfer_topic(),
            address_to_topic(from),
            address_to_topic(to),
        ]),
        log_data: Some(amount_data),
        call_input_selector: None,
    }
}

/// Build an RpcLog representing a Transfer event.
fn make_rpc_transfer_log(token: Address, from: Address, to: Address, amount: U256) -> RpcLog {
    RpcLog {
        address: token,
        topics: vec![
            transfer_topic(),
            address_to_topic(from),
            address_to_topic(to),
        ],
        data: amount.to_big_endian().to_vec(),
    }
}

/// Build an RpcLog with a non-Transfer topic (e.g. Approval).
fn make_rpc_approval_log(token: Address) -> RpcLog {
    // keccak256("Approval(address,address,uint256)") = 0x8c5be1e5...
    let mut approval_topic = [0u8; 32];
    approval_topic[0] = 0x8c;
    approval_topic[1] = 0x5b;
    approval_topic[2] = 0xe1;
    approval_topic[3] = 0xe5;

    RpcLog {
        address: token,
        topics: vec![
            H256::from(approval_topic),
            address_to_topic(addr(0xA)),
            address_to_topic(addr(0xB)),
        ],
        data: U256::from(1000).to_big_endian().to_vec(),
    }
}

/// Build a minimal ReplayTrace with the new fields.
fn make_trace_with_fallback(
    steps: Vec<StepRecord>,
    success: bool,
    success_override: Option<bool>,
    receipt_fund_flows: Vec<FundFlow>,
    data_quality: DataQuality,
) -> ReplayTrace {
    ReplayTrace {
        steps,
        config: ReplayConfig::default(),
        gas_used: 350_688,
        success,
        output: Bytes::new(),
        success_override,
        receipt_fund_flows,
        data_quality,
    }
}

// ============================================================
// 1. Transfer log parsing tests
// ============================================================

#[test]
fn test_parse_transfer_log_40k_aave() {
    // Simulates the 40,000 AAVE transfer from the bug TX.
    // AAVE has 18 decimals: 40_000 * 10^18
    let aave_token = addr(0x7FC6);
    let from = addr(0x25F2);
    let to = addr(0xAAA9);
    let amount = U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18));

    let steps = vec![make_transfer_step(0, aave_token, from, to, amount)];
    let flows = FundFlowTracer::trace(&steps);

    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].from, from);
    assert_eq!(flows[0].to, to);
    assert_eq!(flows[0].token, Some(aave_token));
    assert_eq!(flows[0].value, amount);
}

#[test]
fn test_parse_transfer_log_multiple_transfers() {
    // Simulates multiple transfers as seen in the Aave V3 bug TX.
    let weth = addr(0xC02A);
    let aweth = addr(0x4D5F);
    let user_a = addr(0x464C);
    let user_b = addr(0xAAA9);
    let user_c = addr(0xD016);

    let steps = vec![
        make_transfer_step(0, aweth, Address::zero(), user_a, U256::from(258)),
        make_transfer_step(
            1,
            aweth,
            user_a,
            user_b,
            U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
        ),
        make_transfer_step(
            2,
            aweth,
            user_b,
            user_c,
            U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
        ),
        make_transfer_step(
            3,
            weth,
            addr(0x4D5F),
            user_c,
            U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
        ),
    ];

    let flows = FundFlowTracer::trace(&steps);

    assert_eq!(flows.len(), 4);
    // Verify chronological order
    for i in 0..flows.len() {
        assert_eq!(flows[i].step_index, i);
    }
    // Verify mint (from zero address)
    assert_eq!(flows[0].from, Address::zero());
    assert_eq!(flows[0].to, user_a);
}

#[test]
fn test_parse_transfer_log_zero_amount() {
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);

    let steps = vec![make_transfer_step(0, token, from, to, U256::zero())];
    let flows = FundFlowTracer::trace(&steps);

    // Zero-amount ERC-20 transfers are still valid events (e.g., approval hooks)
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].value, U256::zero());
}

// ============================================================
// 2. success_override precedence tests
// ============================================================

#[test]
fn test_success_override_takes_precedence_true() {
    let trace = make_trace_with_fallback(
        vec![],
        false,      // LEVM says reverted
        Some(true), // receipt says success
        vec![],
        DataQuality::Medium,
    );

    // effective_success should prefer success_override when present
    let effective = trace.success_override.unwrap_or(trace.success);
    assert!(
        effective,
        "success_override=Some(true) should override success=false"
    );
}

#[test]
fn test_success_override_none_falls_back_to_levm() {
    let trace = make_trace_with_fallback(
        vec![],
        true,
        None, // no override
        vec![],
        DataQuality::High,
    );

    let effective = trace.success_override.unwrap_or(trace.success);
    assert!(effective, "no override → use LEVM success=true");
}

#[test]
fn test_success_override_false_overrides_true() {
    // Edge case: LEVM says success but receipt says reverted (unlikely but possible)
    let trace = make_trace_with_fallback(
        vec![],
        true,        // LEVM says success
        Some(false), // receipt says reverted
        vec![],
        DataQuality::Medium,
    );

    let effective = trace.success_override.unwrap_or(trace.success);
    assert!(
        !effective,
        "success_override=Some(false) should override success=true"
    );
}

// ============================================================
// 3. DataQuality branching tests
// ============================================================

#[test]
fn test_data_quality_high_when_levm_success() {
    let trace = make_trace_with_fallback(vec![], true, None, vec![], DataQuality::High);

    assert_eq!(trace.data_quality, DataQuality::High);
    assert!(trace.success);
    assert!(trace.success_override.is_none());
}

#[test]
fn test_data_quality_medium_when_receipt_fallback() {
    let receipt_flows = vec![FundFlow {
        from: addr(0x1),
        to: addr(0x2),
        value: U256::from(1000),
        token: Some(addr(0xDEAD)),
        step_index: 0,
        event_type: EventType::Unknown,
    }];

    let trace = make_trace_with_fallback(
        vec![], // empty steps — LEVM reverted, no opcode data
        false,
        Some(true),
        receipt_flows,
        DataQuality::Medium,
    );

    assert_eq!(trace.data_quality, DataQuality::Medium);
    assert!(!trace.success);
    assert_eq!(trace.success_override, Some(true));
    assert_eq!(trace.receipt_fund_flows.len(), 1);
}

#[test]
fn test_data_quality_default_is_high() {
    assert_eq!(DataQuality::default(), DataQuality::High);
}

#[test]
fn test_data_quality_low_when_partial_data() {
    let trace = make_trace_with_fallback(
        vec![],
        false,
        None, // no receipt data either
        vec![],
        DataQuality::Low,
    );

    assert_eq!(trace.data_quality, DataQuality::Low);
    assert!(!trace.success);
    assert!(trace.receipt_fund_flows.is_empty());
}

// ============================================================
// 4. receipt_fund_flows precedence tests
// ============================================================

#[test]
fn test_receipt_fund_flows_takes_precedence_when_nonempty() {
    // Scenario: LEVM reverted, opcode-based flows are empty, receipt flows exist.
    let receipt_flows = vec![
        FundFlow {
            from: addr(0x25F2),
            to: addr(0xAAA9),
            value: U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(addr(0x7FC6)),
            step_index: 0,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: addr(0x4D5F),
            to: addr(0xD016),
            value: U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(addr(0xC02A)),
            step_index: 1,
            event_type: EventType::Unknown,
        },
    ];

    let trace = make_trace_with_fallback(
        vec![], // no opcode steps (LEVM reverted)
        false,
        Some(true),
        receipt_flows.clone(),
        DataQuality::Medium,
    );

    // Opcode-based tracing yields nothing
    let opcode_flows = FundFlowTracer::trace(&trace.steps);
    assert!(
        opcode_flows.is_empty(),
        "opcode flows should be empty when LEVM reverted"
    );

    // Receipt flows should be used instead
    assert_eq!(trace.receipt_fund_flows.len(), 2);

    // Simulate the selection logic: use receipt flows when opcode flows are empty
    let effective_flows = if opcode_flows.is_empty() && !trace.receipt_fund_flows.is_empty() {
        &trace.receipt_fund_flows
    } else {
        // In a real scenario this would be a slice reference; here we just test the branch
        panic!("should have used receipt flows");
    };

    assert_eq!(effective_flows.len(), 2);
    assert_eq!(
        effective_flows[0].value,
        U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18))
    );
}

#[test]
fn test_opcode_flows_used_when_receipt_flows_empty() {
    // Scenario: LEVM succeeded, opcode-based flows have data, receipt flows empty.
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);
    let amount = U256::from(5000);

    let steps = vec![make_transfer_step(0, token, from, to, amount)];

    let trace = make_trace_with_fallback(
        steps,
        true,
        None,
        vec![], // no receipt fallback needed
        DataQuality::High,
    );

    let opcode_flows = FundFlowTracer::trace(&trace.steps);
    assert_eq!(opcode_flows.len(), 1);
    assert!(trace.receipt_fund_flows.is_empty());

    // Selection logic: prefer opcode flows when available
    let effective_flows = if opcode_flows.is_empty() && !trace.receipt_fund_flows.is_empty() {
        &trace.receipt_fund_flows
    } else {
        &opcode_flows
    };

    assert_eq!(effective_flows.len(), 1);
    assert_eq!(effective_flows[0].value, amount);
}

#[test]
fn test_both_flows_present_prefers_opcode() {
    // Edge case: both opcode flows and receipt flows exist.
    // Opcode flows are higher fidelity and should be preferred.
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);
    let opcode_amount = U256::from(5000);
    let receipt_amount = U256::from(4999); // slightly different (hypothetical)

    let steps = vec![make_transfer_step(0, token, from, to, opcode_amount)];
    let receipt_flows = vec![FundFlow {
        from,
        to,
        value: receipt_amount,
        token: Some(token),
        step_index: 0,
        event_type: EventType::Unknown,
    }];

    let trace = make_trace_with_fallback(steps, true, None, receipt_flows, DataQuality::High);

    let opcode_flows = FundFlowTracer::trace(&trace.steps);
    assert_eq!(opcode_flows.len(), 1);
    assert_eq!(trace.receipt_fund_flows.len(), 1);

    // Selection logic: opcode flows take priority when non-empty
    let effective_flows = if !opcode_flows.is_empty() {
        &opcode_flows
    } else {
        &trace.receipt_fund_flows
    };

    assert_eq!(effective_flows[0].value, opcode_amount);
}

// ============================================================
// 5. Integration: full fallback scenario
// ============================================================

#[test]
fn test_full_fallback_scenario_aave_v3() {
    // Simulates the complete bug TX scenario:
    // - LEVM reverts (success=false) due to RemoteVmDatabase storage miss
    // - Receipt shows success (status=0x1)
    // - Receipt logs contain 6 Transfer events
    // - DataQuality = Medium

    let aave = addr(0x7FC6);
    let weth = addr(0xC02A);
    let aweth = addr(0x4D5F);

    let user_a = addr(0x25F2);
    let user_b = addr(0xAAA9);
    let user_c = addr(0x464C);
    let user_d = addr(0xD016);

    let receipt_flows = vec![
        FundFlow {
            from: user_a,
            to: user_b,
            value: U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(aave),
            step_index: 0,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: Address::zero(),
            to: user_c,
            value: U256::from(258),
            token: Some(aweth),
            step_index: 1,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: user_c,
            to: user_b,
            value: U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(aweth),
            step_index: 2,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: user_b,
            to: user_d,
            value: U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(aweth),
            step_index: 3,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: user_d,
            to: Address::zero(),
            value: U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(aweth),
            step_index: 4,
            event_type: EventType::Unknown,
        },
        FundFlow {
            from: addr(0x4D5F),
            to: user_d,
            value: U256::from(1_500u64) * U256::from(10u64).pow(U256::from(18)),
            token: Some(weth),
            step_index: 5,
            event_type: EventType::Unknown,
        },
    ];

    let trace = make_trace_with_fallback(
        vec![],     // LEVM reverted, no opcode steps captured
        false,      // LEVM says reverted
        Some(true), // receipt says success
        receipt_flows,
        DataQuality::Medium,
    );

    // Verify all conditions for fallback
    assert!(!trace.success, "LEVM should report revert");
    assert_eq!(
        trace.success_override,
        Some(true),
        "receipt should show success"
    );
    assert_eq!(trace.data_quality, DataQuality::Medium);
    assert_eq!(
        trace.receipt_fund_flows.len(),
        6,
        "should have 6 Transfer events"
    );

    // Effective success
    let effective = trace.success_override.unwrap_or(trace.success);
    assert!(effective, "effective status should be success");

    // Opcode flows empty
    let opcode_flows = FundFlowTracer::trace(&trace.steps);
    assert!(opcode_flows.is_empty());

    // Receipt flows should be selected
    let effective_flows = if opcode_flows.is_empty() && !trace.receipt_fund_flows.is_empty() {
        &trace.receipt_fund_flows
    } else {
        &opcode_flows
    };

    assert_eq!(effective_flows.len(), 6);

    // Verify the AAVE transfer (40,000 * 10^18)
    let aave_flow = &effective_flows[0];
    assert_eq!(aave_flow.token, Some(aave));
    assert_eq!(
        aave_flow.value,
        U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18))
    );

    // Verify the mint (from zero address)
    let mint_flow = &effective_flows[1];
    assert_eq!(mint_flow.from, Address::zero());

    // Verify the redeem (to zero address)
    let redeem_flow = &effective_flows[4];
    assert_eq!(redeem_flow.to, Address::zero());
}

// ============================================================
// 6. trace_from_receipt_logs() unit tests
// ============================================================

#[test]
fn test_trace_from_receipt_logs_transfer() {
    let token = addr(0xDEAD);
    let from = addr(0xA);
    let to = addr(0xB);
    let amount = U256::from(40_000u64) * U256::from(10u64).pow(U256::from(18));

    let logs = vec![make_rpc_transfer_log(token, from, to, amount)];
    let flows = FundFlowTracer::trace_from_receipt_logs(&logs);

    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].from, from);
    assert_eq!(flows[0].to, to);
    assert_eq!(flows[0].value, amount);
    assert_eq!(flows[0].token, Some(token));
    assert_eq!(
        flows[0].step_index,
        usize::MAX,
        "receipt flows use usize::MAX as step_index"
    );
}

#[test]
fn test_trace_from_receipt_logs_empty() {
    let flows = FundFlowTracer::trace_from_receipt_logs(&[]);
    assert!(flows.is_empty());
}

#[test]
fn test_trace_from_receipt_logs_non_transfer() {
    let logs = vec![make_rpc_approval_log(addr(0xDEAD))];
    let flows = FundFlowTracer::trace_from_receipt_logs(&logs);
    assert!(
        flows.is_empty(),
        "Approval events should not produce fund flows"
    );
}

#[test]
fn test_trace_from_receipt_logs_multiple_transfers() {
    let token = addr(0xDEAD);
    let logs = vec![
        make_rpc_transfer_log(token, addr(0x1), addr(0x2), U256::from(1000)),
        make_rpc_approval_log(token), // should be filtered out
        make_rpc_transfer_log(token, addr(0x3), addr(0x4), U256::from(2000)),
    ];

    let flows = FundFlowTracer::trace_from_receipt_logs(&logs);
    assert_eq!(
        flows.len(),
        2,
        "should only have Transfer events, not Approval"
    );
    assert_eq!(flows[0].from, addr(0x1));
    assert_eq!(flows[1].from, addr(0x3));
}

#[test]
fn test_trace_from_receipt_logs_insufficient_topics() {
    // LOG with only 2 topics (missing to address) — should be skipped
    let log = RpcLog {
        address: addr(0xDEAD),
        topics: vec![transfer_topic(), address_to_topic(addr(0xA))],
        data: U256::from(100).to_big_endian().to_vec(),
    };
    let flows = FundFlowTracer::trace_from_receipt_logs(&[log]);
    assert!(flows.is_empty(), "logs with < 3 topics should be skipped");
}

#[test]
fn test_trace_from_receipt_logs_short_data() {
    // Transfer log with data shorter than 32 bytes — amount should be zero
    let log = RpcLog {
        address: addr(0xDEAD),
        topics: vec![
            transfer_topic(),
            address_to_topic(addr(0xA)),
            address_to_topic(addr(0xB)),
        ],
        data: vec![0x01, 0x02], // only 2 bytes
    };
    let flows = FundFlowTracer::trace_from_receipt_logs(&[log]);
    assert_eq!(flows.len(), 1);
    assert_eq!(
        flows[0].value,
        U256::zero(),
        "short data should yield zero amount"
    );
}

// ============================================================
// 7. Serialization tests for new fields
// ============================================================

#[test]
fn test_replay_trace_new_fields_serialize() {
    let trace = make_trace_with_fallback(
        vec![],
        false,
        Some(true),
        vec![FundFlow {
            from: addr(0x1),
            to: addr(0x2),
            value: U256::from(1000),
            token: Some(addr(0xDEAD)),
            step_index: usize::MAX,
            event_type: EventType::Unknown,
        }],
        DataQuality::Medium,
    );

    let json = serde_json::to_value(&trace).expect("serialization should succeed");
    assert_eq!(json["success"], false);
    assert_eq!(json["success_override"], true);
    assert_eq!(json["data_quality"], "Medium");
    assert!(json["receipt_fund_flows"].is_array());
    assert_eq!(json["receipt_fund_flows"].as_array().unwrap().len(), 1);
}
