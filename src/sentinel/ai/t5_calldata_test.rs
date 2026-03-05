//! T1: Calldata capture integration tests.

#[cfg(test)]
mod tests {
    use super::super::t5_helpers::*;
    use super::super::types::CallType;
    use ethrex_common::U256;

    /// CALL opcode with call_input_selector set should propagate to CallFrame.
    #[test]
    fn calldata_selector_propagated_for_call() {
        let target = addr(0xCC);
        let selector = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(68_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::Call);
    }

    /// DELEGATECALL with selector propagates to both call_graph and delegatecalls.
    #[test]
    fn calldata_selector_propagated_for_delegatecall() {
        let target = addr(0xDD);
        let selector = [0x12, 0x34, 0x56, 0x78];
        let mut step = make_step(OP_DELEGATECALL, 1, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::from(36_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::DelegateCall);
        assert_eq!(ctx.delegatecalls.len(), 1);
        assert_eq!(ctx.delegatecalls[0].input_selector, Some(selector));
    }

    /// STATICCALL with selector propagates correctly.
    #[test]
    fn calldata_selector_propagated_for_staticcall() {
        let target = addr(0xEE);
        let selector = [0xab, 0xcd, 0xef, 0x01];
        let mut step = make_step(OP_STATICCALL, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::from(4_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::StaticCall);
    }

    /// CALLCODE with selector propagates correctly.
    #[test]
    fn calldata_selector_propagated_for_callcode() {
        let target = addr(0xFF);
        let selector = [0xde, 0xad, 0xbe, 0xef];
        let mut step = make_step(OP_CALLCODE, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(100_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::CallCode);
    }

    /// When call_input_selector is None (input < 4 bytes), CallFrame.input_selector is None.
    #[test]
    fn calldata_selector_none_when_input_too_short() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = None;
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(2_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].input_selector.is_none());
    }

    /// Empty calldata (argsLength = 0) → None selector.
    #[test]
    fn calldata_selector_none_for_empty_calldata() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = None;
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].input_selector.is_none());
    }

    /// Non-call opcode (ADD) never has selector.
    #[test]
    fn calldata_selector_none_for_non_call_opcode() {
        let step = make_step(OP_ADD, 0, addr(0xBB));
        let ctx = extract(&[step]);
        assert!(ctx.call_graph.is_empty());
    }

    /// Mixed trace: some calls have selectors, some don't.
    #[test]
    fn calldata_selectors_mixed_in_trace() {
        let target1 = addr(0xC1);
        let target2 = addr(0xC2);

        let mut step1 = make_step(OP_CALL, 0, addr(0xBB));
        step1.call_input_selector = Some([0xaa, 0xbb, 0xcc, 0xdd]);
        step1.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target1),
            U256::zero(),
            U256::zero(),
            U256::from(68_u64),
            U256::zero(),
            U256::zero(),
        ];

        let mut step2 = make_step(OP_STATICCALL, 1, target1);
        step2.call_input_selector = None;
        step2.stack_top = vec![
            U256::from(30_000_u64),
            u256_addr(target2),
            U256::zero(),
            U256::zero(),
            U256::zero(),
            U256::zero(),
        ];

        let ctx = extract(&[step1, step2]);
        assert_eq!(ctx.call_graph.len(), 2);
        assert_eq!(
            ctx.call_graph[0].input_selector,
            Some([0xaa, 0xbb, 0xcc, 0xdd])
        );
        assert!(ctx.call_graph[1].input_selector.is_none());
    }
}
