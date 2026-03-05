//! Additional tests for Hallucination Guard — complements inline tests in guard.rs.
//!
//! Focuses on integration scenarios and edge cases: composite evidence,
//! from/to address inclusion, ETH transfer amounts, cross-field validation.

#[cfg(test)]
mod tests {
    use crate::sentinel::ai::guard::validate_evidence;
    use crate::sentinel::ai::types::{
        AgentContext, AgentVerdict, AttackType, CallFrame, CallType, ContractCreation, CreateType,
        DelegateCallInfo, EthTransfer, LogEvent, StorageMutation, TokenTransfer,
    };
    use ethrex_common::{Address, H256, U256};

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn format_addr(a: &Address) -> String {
        format!("0x{}", hex::encode(a.as_bytes()))
    }

    fn minimal_context() -> AgentContext {
        AgentContext {
            tx_hash: h256(1),
            block_number: 21_000_000,
            from: addr(0xAA),
            to: Some(addr(0xBB)),
            value_wei: U256::zero(),
            gas_used: 100_000,
            succeeded: true,
            revert_count: 0,
            suspicious_score: 0.3,
            suspicion_reasons: vec![],
            call_graph: vec![],
            storage_mutations: vec![],
            erc20_transfers: vec![],
            eth_transfers: vec![],
            log_events: vec![],
            delegatecalls: vec![],
            contract_creations: vec![],
        }
    }

    fn attack_verdict(evidence: Vec<String>) -> AgentVerdict {
        AgentVerdict {
            is_attack: true,
            confidence: 0.9,
            attack_type: Some(AttackType::Reentrancy),
            reasoning: "test".to_string(),
            evidence,
            evidence_valid: false,
            false_positive_reason: None,
            model_used: "test".to_string(),
            tokens_used: 100,
            latency_ms: 200,
        }
    }

    fn rich_context() -> AgentContext {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![CallFrame {
            depth: 0,
            caller: addr(0xAA),
            target: addr(0xBB),
            value: U256::zero(),
            input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            input_size: 68,
            output_size: 32,
            gas_used: 50_000,
            call_type: CallType::Call,
            reverted: false,
        }];
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0xAA),
            to: addr(0xCC),
            amount: U256::from(1_000_000_000_000_000_000_u64),
        }];
        ctx.eth_transfers = vec![EthTransfer {
            from: addr(0xAA),
            to: addr(0xDD),
            value: U256::from(5_000_000_000_000_000_000_u64),
            call_depth: 1,
        }];
        ctx.storage_mutations = vec![StorageMutation {
            contract: addr(0xBB),
            slot: h256(0x01),
            old_value: h256(0x00),
            new_value: h256(0xFF),
            in_callback: true,
        }];
        ctx.log_events = vec![LogEvent {
            address: addr(0x10),
            topic0: h256(0xAB),
            topics: vec![h256(0xCD)],
            data_size: 64,
        }];
        ctx.delegatecalls = vec![DelegateCallInfo {
            caller: addr(0x01),
            target: addr(0x02),
            input_selector: Some([0x12, 0x34, 0x56, 0x78]),
        }];
        ctx.contract_creations = vec![ContractCreation {
            deployer: addr(0x05),
            deployed: addr(0x06),
            code_size: 1024,
            create_type: CreateType::Create,
        }];
        ctx
    }

    // ── Addresses from all sources ───────────────────────────────────────

    #[test]
    fn from_address_is_valid_reference() {
        let ctx = minimal_context();
        let from_hex = format_addr(&addr(0xAA));
        let verdict = attack_verdict(vec![format!("Transaction from {from_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn to_address_is_valid_reference() {
        let ctx = minimal_context();
        let to_hex = format_addr(&addr(0xBB));
        let verdict = attack_verdict(vec![format!("CALL to {to_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn storage_mutation_contract_is_valid_reference() {
        let ctx = rich_context();
        let addr_hex = format_addr(&addr(0xBB));
        let verdict = attack_verdict(vec![format!("SSTORE on contract {addr_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn contract_creation_deployer_is_valid() {
        let mut ctx = minimal_context();
        ctx.contract_creations = vec![ContractCreation {
            deployer: addr(0x05),
            deployed: addr(0x06),
            code_size: 1024,
            create_type: CreateType::Create,
        }];
        let deployer_hex = format_addr(&addr(0x05));
        let verdict = attack_verdict(vec![format!(
            "Contract deployed by {deployer_hex} is suspicious"
        )]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn contract_creation_deployed_is_valid() {
        let mut ctx = minimal_context();
        ctx.contract_creations = vec![ContractCreation {
            deployer: addr(0x05),
            deployed: addr(0x06),
            code_size: 1024,
            create_type: CreateType::Create,
        }];
        let deployed_hex = format_addr(&addr(0x06));
        let verdict = attack_verdict(vec![format!(
            "New contract at {deployed_hex} is suspicious"
        )]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn log_event_address_is_valid() {
        let mut ctx = minimal_context();
        ctx.log_events = vec![LogEvent {
            address: addr(0x10),
            topic0: h256(0xAB),
            topics: vec![],
            data_size: 64,
        }];
        let log_addr_hex = format_addr(&addr(0x10));
        let verdict = attack_verdict(vec![format!(
            "Event emitted by {log_addr_hex} is suspicious"
        )]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn delegatecall_target_is_valid() {
        let mut ctx = minimal_context();
        ctx.delegatecalls = vec![DelegateCallInfo {
            caller: addr(0x01),
            target: addr(0x02),
            input_selector: None,
        }];
        let dc_target_hex = format_addr(&addr(0x02));
        let verdict = attack_verdict(vec![format!(
            "DELEGATECALL to {dc_target_hex} is suspicious"
        )]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    // ── Amount validation edge cases ─────────────────────────────────────

    #[test]
    fn eth_transfer_amount_is_valid() {
        let ctx = rich_context();
        // 5 ETH = 5000000000000000000
        let verdict = attack_verdict(vec!["ETH transfer of 5000000000000000000 wei".to_string()]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn amount_slightly_outside_10_percent_fails() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_u64),
        }];
        // 889999 is just outside 10% below (900000 is the boundary)
        let verdict = attack_verdict(vec!["Transfer of 889999 tokens".to_string()]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    // ── Composite: multiple evidence with different claim types ──────────

    #[test]
    fn composite_address_and_selector_passes() {
        let ctx = rich_context();
        let addr_hex = format_addr(&addr(0xBB));
        let verdict = attack_verdict(vec![format!("CALL to {addr_hex} with function 0xdeadbeef")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn composite_valid_address_and_invalid_selector_fails() {
        let ctx = rich_context();
        let addr_hex = format_addr(&addr(0xBB));
        let verdict = attack_verdict(vec![format!("CALL to {addr_hex} with function 0xaabbccdd")]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn composite_all_types_valid() {
        let ctx = rich_context();
        let addr_hex = format_addr(&addr(0xBB));
        let topic_hex = format!("0x{}", hex::encode(h256(0xAB).as_bytes()));
        let verdict = attack_verdict(vec![
            format!("CALL to {addr_hex}"),
            format!("Event with topic {topic_hex}"),
            "Function selector 0xdeadbeef used".to_string(),
            "Transfer amount 1000000000000000000".to_string(),
        ]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    // ── Qualitative evidence (no verifiable claims) ──────────────────────

    #[test]
    fn qualitative_evidence_passes_soft() {
        let ctx = minimal_context();
        let verdict = attack_verdict(vec![
            "High gas usage pattern detected".to_string(),
            "Multiple internal reverts observed".to_string(),
        ]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    // ── Topic in nested topics list ──────────────────────────────────────

    #[test]
    fn indexed_topic_from_topics_array_is_valid() {
        let ctx = rich_context();
        // h256(0xCD) is in log_events[0].topics (indexed parameter)
        let topic_hex = format!("0x{}", hex::encode(h256(0xCD).as_bytes()));
        let verdict = attack_verdict(vec![format!("Indexed param {topic_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    // ── Small amounts are not extracted ──────────────────────────────────

    #[test]
    fn small_numbers_not_treated_as_amounts() {
        let ctx = minimal_context();
        // Numbers < 4 digits are not extracted as amounts
        let verdict = attack_verdict(vec!["Call depth was 3".to_string()]);
        assert!(validate_evidence(&verdict, &ctx)); // soft pass (no verifiable claims)
    }

    // ── ContextExtractor → Guard integration ───────────────────────────

    #[test]
    fn extractor_produces_none_selectors_guard_soft_passes() {
        // ContextExtractor currently returns input_selector=None for all calls
        // (calldata capture not yet implemented — TODO phase2).
        // Verify Guard doesn't reject selector evidence in this scenario.
        use crate::sentinel::ai::context::{ContextExtractor, ExtractParams};
        use crate::types::StepRecord;

        let call_step = StepRecord {
            step_index: 0,
            pc: 0,
            opcode: 0xF1, // CALL
            depth: 0,
            gas_remaining: 1_000_000,
            stack_top: vec![
                ethrex_common::U256::zero(),
                ethrex_common::U256::from_big_endian(addr(0xBB).as_bytes()),
                ethrex_common::U256::zero(),
                ethrex_common::U256::zero(),       // argsOffset
                ethrex_common::U256::from(68_u64), // argsLength (>= 4)
                ethrex_common::U256::zero(),       // retOffset
                ethrex_common::U256::from(32_u64), // retLength
            ],
            stack_depth: 7,
            memory_size: 0,
            code_address: addr(0xAA),
            call_value: None,
            storage_writes: None,
            log_topics: None,
            log_data: None,
            call_input_selector: None,
        };

        let ctx = ContextExtractor::extract(
            &[call_step],
            ExtractParams {
                tx_hash: h256(1),
                block_number: 100,
                from: addr(0xAA),
                to: Some(addr(0xBB)),
                value_wei: ethrex_common::U256::zero(),
                gas_used: 50_000,
                succeeded: true,
                suspicious_score: 0.5,
                suspicion_reasons: vec![],
            },
        );

        // Confirm extractor produces None selectors
        assert!(
            ctx.call_graph.iter().all(|f| f.input_selector.is_none()),
            "ContextExtractor should return None selectors (phase2 TODO)"
        );

        // Guard should soft-pass evidence mentioning a selector,
        // because known_selectors is empty and the skip-guard applies.
        let verdict = attack_verdict(vec!["Function call 0xa9059cbb detected".to_string()]);
        assert!(
            validate_evidence(&verdict, &ctx),
            "Guard should soft-pass selector evidence when extractor cannot provide selectors"
        );
    }
}
