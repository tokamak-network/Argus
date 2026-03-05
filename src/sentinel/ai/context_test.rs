//! Additional tests for ContextExtractor — complements inline tests in context.rs.
//!
//! Focuses on: multi-opcode traces, CALLCODE extraction, CREATE2,
//! mixed call types, gas estimation, and context size with realistic complexity.

#[cfg(test)]
mod tests {
    use crate::sentinel::ai::context::{ContextExtractor, ExtractParams};
    use crate::sentinel::ai::types::{CallType, CreateType};
    use crate::types::{StepRecord, StorageWrite};
    use ethrex_common::{Address, H256, U256};

    const OP_CALL: u8 = 0xF1;
    const OP_CALLCODE: u8 = 0xF2;
    const OP_DELEGATECALL: u8 = 0xF4;
    const OP_STATICCALL: u8 = 0xFA;
    const OP_CREATE: u8 = 0xF0;
    const OP_CREATE2: u8 = 0xF5;
    const OP_SSTORE: u8 = 0x55;
    const OP_REVERT: u8 = 0xFD;
    const OP_ADD: u8 = 0x01;
    const OP_LOG3: u8 = 0xA3;

    const TRANSFER_TOPIC: [u8; 32] = [
        0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d,
        0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23,
        0xb3, 0xef,
    ];

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn u256_to_stack_entry(a: Address) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(a.as_bytes());
        U256::from_big_endian(&bytes)
    }

    fn make_step(opcode: u8, depth: usize, code_addr: Address) -> StepRecord {
        StepRecord {
            step_index: 0,
            pc: 0,
            opcode,
            depth,
            gas_remaining: 100_000,
            stack_top: vec![],
            stack_depth: 0,
            memory_size: 0,
            code_address: code_addr,
            call_value: None,
            storage_writes: None,
            log_topics: None,
            log_data: None,
            call_input_selector: None,
        }
    }

    fn extract(steps: &[StepRecord]) -> crate::sentinel::ai::types::AgentContext {
        ContextExtractor::extract(
            steps,
            ExtractParams {
                tx_hash: h256(0x01),
                block_number: 21_000_000,
                from: addr(0xAA),
                to: Some(addr(0xBB)),
                value_wei: U256::zero(),
                gas_used: 100_000,
                succeeded: true,
                suspicious_score: 0.5,
                suspicion_reasons: vec!["test".to_string()],
            },
        )
    }

    // ── CALLCODE extraction ──────────────────────────────────────────────

    #[test]
    fn callcode_extracted_as_call_frame() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALLCODE, 0, addr(0xBB));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::from(4_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].call_type, CallType::CallCode);
        assert_eq!(ctx.call_graph[0].target, target);
    }

    // ── Multiple call types in one trace ─────────────────────────────────

    #[test]
    fn mixed_call_types_extracted_correctly() {
        let target_call = addr(0xC1);
        let target_static = addr(0xC2);
        let target_delegate = addr(0xC3);

        let mut call_step = make_step(OP_CALL, 0, addr(0xBB));
        call_step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target_call),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let mut static_step = make_step(OP_STATICCALL, 1, addr(0xC1));
        static_step.stack_top = vec![
            U256::from(30_000_u64),
            u256_to_stack_entry(target_static),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let mut delegate_step = make_step(OP_DELEGATECALL, 1, addr(0xC1));
        delegate_step.stack_top = vec![
            U256::from(30_000_u64),
            u256_to_stack_entry(target_delegate),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let ctx = extract(&[call_step, static_step, delegate_step]);
        assert_eq!(ctx.call_graph.len(), 3);
        assert_eq!(ctx.call_graph[0].call_type, CallType::Call);
        assert_eq!(ctx.call_graph[1].call_type, CallType::StaticCall);
        assert_eq!(ctx.call_graph[2].call_type, CallType::DelegateCall);

        // DELEGATECALL also appears in delegatecalls list
        assert_eq!(ctx.delegatecalls.len(), 1);
        assert_eq!(ctx.delegatecalls[0].target, target_delegate);
    }

    // ── Multiple storage mutations ───────────────────────────────────────

    #[test]
    fn multiple_sstores_at_different_depths() {
        let mut step0 = make_step(OP_SSTORE, 0, addr(0xBB));
        step0.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x01),
            old_value: U256::zero(),
            new_value: U256::from(1_u64),
        }]);

        let mut step1 = make_step(OP_SSTORE, 1, addr(0xBB));
        step1.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x02),
            old_value: U256::zero(),
            new_value: U256::from(2_u64),
        }]);

        let mut step2 = make_step(OP_SSTORE, 2, addr(0xBB));
        step2.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x03),
            old_value: U256::zero(),
            new_value: U256::from(3_u64),
        }]);

        let ctx = extract(&[step0, step1, step2]);
        assert_eq!(ctx.storage_mutations.len(), 3);
        assert!(!ctx.storage_mutations[0].in_callback);
        assert!(ctx.storage_mutations[1].in_callback); // depth 1 > first sstore depth 0
        assert!(ctx.storage_mutations[2].in_callback); // depth 2 > first sstore depth 0
    }

    // ── ERC-20 Transfer with zero amount ─────────────────────────────────

    #[test]
    fn erc20_transfer_with_empty_log_data_gives_zero_amount() {
        let from = addr(0x11);
        let to = addr(0x22);
        let mut from_h256 = [0u8; 32];
        from_h256[12..32].copy_from_slice(from.as_bytes());
        let mut to_h256 = [0u8; 32];
        to_h256[12..32].copy_from_slice(to.as_bytes());

        let mut step = make_step(OP_LOG3, 0, addr(0x10));
        step.log_topics = Some(vec![
            H256::from(TRANSFER_TOPIC),
            H256::from(from_h256),
            H256::from(to_h256),
        ]);
        step.log_data = Some(vec![]); // empty data

        let ctx = extract(&[step]);
        assert_eq!(ctx.erc20_transfers.len(), 1);
        assert_eq!(ctx.erc20_transfers[0].amount, U256::zero());
    }

    // ── Revert detection with nested calls ───────────────────────────────

    #[test]
    fn call_revert_detected_at_correct_depth() {
        let target = addr(0xCC);
        let mut call_step = make_step(OP_CALL, 0, addr(0xBB));
        call_step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let add_step = make_step(OP_ADD, 1, target); // inside the call
        let revert_step = make_step(OP_REVERT, 1, target); // revert inside call

        let ctx = extract(&[call_step, add_step, revert_step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].reverted);
        assert_eq!(ctx.revert_count, 1);
    }

    #[test]
    fn call_without_revert_is_not_reverted() {
        let target = addr(0xCC);
        let mut call_step = make_step(OP_CALL, 0, addr(0xBB));
        call_step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let add_step = make_step(OP_ADD, 1, target);
        let return_step = make_step(OP_ADD, 0, addr(0xBB)); // return to caller depth

        let ctx = extract(&[call_step, add_step, return_step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(!ctx.call_graph[0].reverted);
    }

    // ── CREATE2 extraction ───────────────────────────────────────────────

    #[test]
    fn create2_extracted_with_code_size() {
        let mut step = make_step(OP_CREATE2, 0, addr(0xBB));
        step.stack_top = vec![
            U256::zero(),         // value
            U256::from(0_u64),    // offset
            U256::from(1024_u64), // length
            U256::from(42_u64),   // salt
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.contract_creations.len(), 1);
        assert_eq!(ctx.contract_creations[0].create_type, CreateType::Create2);
        assert_eq!(ctx.contract_creations[0].code_size, 1024);
        assert_eq!(ctx.contract_creations[0].deployer, addr(0xBB));
    }

    // ── Gas estimation ───────────────────────────────────────────────────

    #[test]
    fn gas_estimated_from_gas_remaining_delta() {
        let target = addr(0xCC);
        let mut call_step = make_step(OP_CALL, 0, addr(0xBB));
        call_step.gas_remaining = 80_000;
        call_step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let mut return_step = make_step(OP_ADD, 0, addr(0xBB));
        return_step.gas_remaining = 60_000;

        let ctx = extract(&[call_step, return_step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].gas_used, 20_000); // 80000 - 60000
    }

    // ── Context size with realistic complexity ───────────────────────────

    #[test]
    fn complex_trace_context_within_6kb() {
        let mut steps = Vec::new();

        // 10 CALL steps
        for i in 0..10_u8 {
            let target = addr(i + 0x10);
            let mut step = make_step(OP_CALL, usize::from(i % 3), addr(i));
            step.stack_top = vec![
                U256::from(50_000_u64),
                u256_to_stack_entry(target),
                U256::zero(),
                U256::zero(),
                U256::from(68_u64),
                U256::zero(),
                U256::from(32_u64),
            ];
            steps.push(step);

            // SSTORE after each call
            let mut sstore = make_step(OP_SSTORE, usize::from(i % 3), target);
            sstore.storage_writes = Some(vec![StorageWrite {
                address: target,
                slot: h256(i),
                old_value: U256::zero(),
                new_value: U256::from(u64::from(i)),
            }]);
            steps.push(sstore);
        }

        // 3 REVERT steps
        for _ in 0..3 {
            steps.push(make_step(OP_REVERT, 1, addr(0x10)));
        }

        let ctx = extract(&steps);
        let size = ctx.approx_json_bytes().unwrap();
        assert!(size <= 6_144, "context size {size} exceeds 6KB ceiling");
        assert_eq!(ctx.call_graph.len(), 10);
        assert_eq!(ctx.storage_mutations.len(), 10);
        assert_eq!(ctx.revert_count, 3);
    }

    // ── Metadata passthrough ─────────────────────────────────────────────

    #[test]
    fn contract_creation_tx_has_none_to() {
        let ctx = ContextExtractor::extract(
            &[],
            ExtractParams {
                tx_hash: h256(0x42),
                block_number: 99_999,
                from: addr(0x11),
                to: None,
                value_wei: U256::from(123_u64),
                gas_used: 42_000,
                succeeded: false,
                suspicious_score: 0.75,
                suspicion_reasons: vec!["high gas".to_string()],
            },
        );

        assert!(ctx.to.is_none());
        assert_eq!(ctx.block_number, 99_999);
        assert!(!ctx.succeeded);
        assert!((ctx.suspicious_score - 0.75).abs() < f64::EPSILON);
        assert_eq!(ctx.suspicion_reasons.len(), 1);
    }

    // ── Root call uses tx_from ───────────────────────────────────────────

    #[test]
    fn root_call_caller_is_tx_from() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph[0].caller, addr(0xAA)); // tx_from, not code_address
    }

    // ── Tests migrated from context.rs inline tests ─────────────────────

    #[test]
    fn extract_empty_trace() {
        let ctx = extract(&[]);
        assert!(ctx.call_graph.is_empty());
        assert!(ctx.storage_mutations.is_empty());
        assert_eq!(ctx.revert_count, 0);
    }

    #[test]
    fn extract_call_frame_basic() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::from(1000_u64),
            U256::zero(),
            U256::from(4_u64),
            U256::zero(),
            U256::from(32_u64),
        ];
        step.call_value = Some(U256::from(1000_u64));

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        let frame = &ctx.call_graph[0];
        assert_eq!(frame.call_type, CallType::Call);
        assert_eq!(frame.target, target);
        assert_eq!(frame.value, U256::from(1000_u64));
        assert_eq!(frame.caller, addr(0xAA)); // Root call uses tx_from
        assert_eq!(frame.input_size, 4);
        assert_eq!(frame.output_size, 32);
    }

    #[test]
    fn extract_delegatecall_basic() {
        let target = addr(0xDD);
        let mut step = make_step(OP_DELEGATECALL, 1, addr(0xBB));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::from(36_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.delegatecalls.len(), 1);
        assert_eq!(ctx.delegatecalls[0].target, target);
        assert_eq!(ctx.delegatecalls[0].caller, addr(0xBB));
    }

    #[test]
    fn extract_staticcall_basic() {
        let target = addr(0xEE);
        let mut step = make_step(OP_STATICCALL, 0, addr(0xBB));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::from(4_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].call_type, CallType::StaticCall);
        assert_eq!(ctx.call_graph[0].target, target);
    }

    #[test]
    fn extract_sstore_basic() {
        let mut step = make_step(OP_SSTORE, 0, addr(0xBB));
        step.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x01),
            old_value: U256::zero(),
            new_value: U256::from(42_u64),
        }]);

        let ctx = extract(&[step]);
        assert_eq!(ctx.storage_mutations.len(), 1);
        assert_eq!(ctx.storage_mutations[0].contract, addr(0xBB));
        assert_eq!(ctx.storage_mutations[0].slot, h256(0x01));
        assert!(!ctx.storage_mutations[0].in_callback);
    }

    #[test]
    fn sstore_in_callback_detected_basic() {
        let mut step1 = make_step(OP_SSTORE, 0, addr(0xBB));
        step1.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x01),
            old_value: U256::zero(),
            new_value: U256::from(1_u64),
        }]);

        let mut step2 = make_step(OP_SSTORE, 2, addr(0xBB));
        step2.storage_writes = Some(vec![StorageWrite {
            address: addr(0xBB),
            slot: h256(0x01),
            old_value: U256::from(1_u64),
            new_value: U256::from(2_u64),
        }]);

        let ctx = extract(&[step1, step2]);
        assert_eq!(ctx.storage_mutations.len(), 2);
        assert!(!ctx.storage_mutations[0].in_callback);
        assert!(ctx.storage_mutations[1].in_callback);
    }

    #[test]
    fn extract_erc20_transfer_basic() {
        let from = addr(0x11);
        let to = addr(0x22);

        let mut from_h256 = [0u8; 32];
        from_h256[12..32].copy_from_slice(from.as_bytes());
        let mut to_h256 = [0u8; 32];
        to_h256[12..32].copy_from_slice(to.as_bytes());

        let mut step = make_step(OP_LOG3, 0, addr(0x10));
        step.log_topics = Some(vec![
            H256::from(TRANSFER_TOPIC),
            H256::from(from_h256),
            H256::from(to_h256),
        ]);
        let mut amount_bytes = [0u8; 32];
        amount_bytes[31] = 0xE8;
        amount_bytes[30] = 0x03; // 1000
        step.log_data = Some(amount_bytes.to_vec());

        let ctx = extract(&[step]);
        assert_eq!(ctx.erc20_transfers.len(), 1);
        assert_eq!(ctx.erc20_transfers[0].token, addr(0x10));
        assert_eq!(ctx.erc20_transfers[0].from, from);
        assert_eq!(ctx.erc20_transfers[0].to, to);
        assert_eq!(ctx.erc20_transfers[0].amount, U256::from(1000_u64));
    }

    #[test]
    fn extract_non_transfer_log_basic() {
        let swap_topic = h256(0xCC);
        let mut step = make_step(0xA2, 0, addr(0xBB)); // LOG2
        step.log_topics = Some(vec![swap_topic, h256(0x01)]);
        step.log_data = Some(vec![0u8; 64]);

        let ctx = extract(&[step]);
        assert!(ctx.erc20_transfers.is_empty());
        assert_eq!(ctx.log_events.len(), 1);
        assert_eq!(ctx.log_events[0].topic0, swap_topic);
        assert_eq!(ctx.log_events[0].data_size, 64);
    }

    #[test]
    fn extract_eth_transfer_basic() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_value = Some(U256::from(1_000_000_u64));
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::from(1_000_000_u64),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.eth_transfers.len(), 1);
        assert_eq!(ctx.eth_transfers[0].value, U256::from(1_000_000_u64));
        assert_eq!(ctx.eth_transfers[0].to, target);
    }

    #[test]
    fn no_eth_transfer_for_zero_value_basic() {
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_value = Some(U256::zero());
        step.stack_top = vec![U256::from(50_000_u64), U256::zero()];

        let ctx = extract(&[step]);
        assert!(ctx.eth_transfers.is_empty());
    }

    #[test]
    fn count_reverts_in_trace_basic() {
        let steps = vec![
            make_step(OP_CALL, 0, addr(0xBB)),
            make_step(OP_REVERT, 1, addr(0xBB)),
            make_step(OP_CALL, 0, addr(0xBB)),
            make_step(OP_REVERT, 1, addr(0xBB)),
            make_step(OP_REVERT, 0, addr(0xBB)),
        ];

        let ctx = extract(&steps);
        assert_eq!(ctx.revert_count, 3);
    }

    #[test]
    fn extract_create_basic() {
        let mut step = make_step(OP_CREATE, 0, addr(0xBB));
        step.stack_top = vec![U256::zero(), U256::from(0_u64), U256::from(256_u64)];

        let ctx = extract(&[step]);
        assert_eq!(ctx.contract_creations.len(), 1);
        assert_eq!(ctx.contract_creations[0].create_type, CreateType::Create);
        assert_eq!(ctx.contract_creations[0].code_size, 256);
        assert_eq!(ctx.contract_creations[0].deployer, addr(0xBB));
    }

    #[test]
    fn call_reverted_detected_basic() {
        let target = addr(0xCC);
        let mut call_step = make_step(OP_CALL, 0, addr(0xBB));
        call_step.stack_top = vec![
            U256::from(50_000_u64),
            u256_to_stack_entry(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let revert_step = make_step(OP_REVERT, 1, target);

        let ctx = extract(&[call_step, revert_step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].reverted);
    }

    #[test]
    fn extracted_context_json_size_reasonable() {
        let ctx = extract(&[]);
        let size = ctx.approx_json_bytes().unwrap();
        assert!(size < 6_144, "minimal context should be < 6KB, got {size}");
    }
}
