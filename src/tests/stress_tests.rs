//! Large trace stress tests for performance validation.
//!
//! Verifies that classification, fund flow tracing, and report generation
//! complete within acceptable time and memory bounds.

use ethrex_common::{Address, H256, U256};

use crate::types::StepRecord;

use crate::autopsy::{
    classifier::AttackClassifier, fund_flow::FundFlowTracer, report::AutopsyReport,
};

fn addr(n: u64) -> Address {
    Address::from_low_u64_be(n)
}

fn make_large_trace(step_count: usize) -> Vec<StepRecord> {
    let mut steps = Vec::with_capacity(step_count);
    let contracts = [addr(0x10), addr(0x20), addr(0x30), addr(0x40), addr(0x50)];

    for i in 0..step_count {
        let opcode = match i % 20 {
            0 => 0xF1, // CALL
            1 => 0xFA, // STATICCALL
            2 => 0x54, // SLOAD
            3 => 0x55, // SSTORE
            4 => 0xA3, // LOG3
            _ => 0x01, // ADD (filler)
        };
        let depth = (i % 5) as usize;
        let contract = contracts[i % contracts.len()];

        steps.push(StepRecord {
            step_index: i,
            pc: i * 2,
            opcode,
            depth,
            gas_remaining: 10_000_000 - (i as i64),
            stack_top: vec![
                U256::from(i as u64),
                U256::from_big_endian(contract.as_bytes()),
            ],
            stack_depth: 2,
            memory_size: 64,
            code_address: contract,
            call_value: if opcode == 0xF1 {
                Some(U256::from(100))
            } else {
                None
            },
            storage_writes: None,
            log_topics: if opcode == 0xA3 {
                Some(vec![H256::zero(), H256::zero(), H256::zero()])
            } else {
                None
            },
            log_data: None,
        });
    }
    steps
}

#[test]
fn test_classification_100k_steps_under_5s() {
    let steps = make_large_trace(100_000);

    let start = std::time::Instant::now();
    let _patterns = AttackClassifier::classify(&steps);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 5,
        "classification of 100k steps should complete in <5s, took {elapsed:?}"
    );
}

#[test]
fn test_report_generation_100k_steps_under_1s() {
    let steps = make_large_trace(100_000);
    let patterns = AttackClassifier::classify(&steps);
    let flows = FundFlowTracer::trace(&steps);

    let start = std::time::Instant::now();
    let report = AutopsyReport::build(H256::zero(), 12345, &steps, patterns, flows, vec![]);
    let _md = report.to_markdown();
    let _json = report.to_json().unwrap();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 1000,
        "report generation should complete in <1s, took {elapsed:?}"
    );
}

#[test]
fn test_fund_flow_tracing_100k_steps() {
    let steps = make_large_trace(100_000);

    let start = std::time::Instant::now();
    let flows = FundFlowTracer::trace(&steps);
    let elapsed = start.elapsed();

    // Should find some flows from the CALL steps
    assert!(!flows.is_empty(), "should detect fund flows in large trace");
    assert!(
        elapsed.as_secs() < 2,
        "fund flow tracing should complete in <2s, took {elapsed:?}"
    );
}

#[test]
fn test_stress_timeout_guard() {
    // Verify 10k steps completes near-instantly (sanity check)
    let steps = make_large_trace(10_000);

    let start = std::time::Instant::now();
    let patterns = AttackClassifier::classify(&steps);
    let flows = FundFlowTracer::trace(&steps);
    let report = AutopsyReport::build(H256::zero(), 1, &steps, patterns, flows, vec![]);
    let _md = report.to_markdown();
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 500,
        "10k steps should complete in <500ms, took {elapsed:?}"
    );
    assert!(report.total_steps == 10_000);
}
