//! [`OpcodeRecorder`] implementation that captures [`StepRecord`]s.

use crate::opcodes::{
    OP_CALL, OP_CALLCODE, OP_CREATE, OP_CREATE2, OP_DELEGATECALL, OP_LOG0, OP_LOG4, OP_SSTORE,
    OP_STATICCALL,
};
use crate::types::{ReplayConfig, StepRecord, StorageWrite};
use ethrex_common::{Address, H256, U256};
use ethrex_levm::call_frame::Stack;
use ethrex_levm::debugger_hook::OpcodeRecorder;
use ethrex_levm::memory::Memory;

/// Maximum LOG data bytes to capture per step (prevents memory bloat).
const MAX_LOG_DATA_CAPTURE: usize = 256;

/// Records each opcode step into a `Vec<StepRecord>`.
pub struct DebugRecorder {
    pub steps: Vec<StepRecord>,
    config: ReplayConfig,
}

impl DebugRecorder {
    pub fn new(config: ReplayConfig) -> Self {
        Self {
            steps: Vec::new(),
            config,
        }
    }

    fn capture_stack_top(&self, stack: &Stack) -> Vec<U256> {
        let depth = stack.len();
        let n = self.config.stack_top_capture.min(depth);
        let mut top = Vec::with_capacity(n);
        for i in 0..n {
            if let Some(val) = stack.peek(i) {
                top.push(val);
            }
        }
        top
    }

    /// Extract call_value for CALL/CREATE opcodes from pre-execution stack.
    fn extract_call_value(opcode: u8, stack: &Stack) -> Option<U256> {
        match opcode {
            // CALL: stack[0]=gas, stack[1]=to, stack[2]=value
            OP_CALL | OP_CALLCODE => stack.peek(2),
            // CREATE/CREATE2: stack[0]=value
            OP_CREATE | OP_CREATE2 => stack.peek(0),
            // DELEGATECALL/STATICCALL don't transfer value
            _ => None,
        }
    }

    /// Extract log topics for LOG0-LOG4 opcodes from pre-execution stack.
    fn extract_log_topics(opcode: u8, stack: &Stack) -> Option<Vec<H256>> {
        if !(OP_LOG0..=OP_LOG4).contains(&opcode) {
            return None;
        }
        let topic_count = (opcode - OP_LOG0) as usize;
        if topic_count == 0 {
            return Some(Vec::new());
        }
        // LOG stack: [offset, size, topic0, topic1, ...]
        let mut topics = Vec::with_capacity(topic_count);
        for i in 0..topic_count {
            if let Some(val) = stack.peek(2 + i) {
                let bytes = val.to_big_endian();
                topics.push(H256::from(bytes));
            }
        }
        Some(topics)
    }

    /// Extract log data bytes from memory for LOG0-LOG4 opcodes.
    /// Stack layout: [offset, size, topic0, ...]
    /// Cap at MAX_LOG_DATA_CAPTURE bytes to prevent bloat.
    fn extract_log_data(opcode: u8, stack: &Stack, memory: &Memory) -> Option<Vec<u8>> {
        if !(OP_LOG0..=OP_LOG4).contains(&opcode) {
            return None;
        }
        let offset = stack.peek(0)?.as_usize();
        let size = stack.peek(1)?.as_usize();
        if size == 0 {
            return Some(Vec::new());
        }
        let capped_size = size.min(MAX_LOG_DATA_CAPTURE);
        // Read from memory buffer directly (read-only, no expansion)
        let buf = memory.buffer.borrow();
        let base = memory.current_base_offset();
        let start = base + offset;
        let end = start + capped_size;
        if end <= buf.len() {
            Some(buf[start..end].to_vec())
        } else if start < buf.len() {
            // Partial read — memory not fully expanded yet
            let mut data = buf[start..].to_vec();
            data.resize(capped_size, 0);
            Some(data)
        } else {
            // Offset beyond current memory — return zeros
            Some(vec![0u8; capped_size])
        }
    }

    /// Extract the first 4 bytes (function selector) from CALL-family input data in memory.
    ///
    /// CALL/CALLCODE stack: [gas, to, value, argsOffset, argsLength, retOffset, retLength]
    /// DELEGATECALL/STATICCALL stack: [gas, to, argsOffset, argsLength, retOffset, retLength]
    ///
    /// Returns `None` if the opcode is not a call, argsLength < 4, or memory is inaccessible.
    fn extract_call_input_selector(opcode: u8, stack: &Stack, memory: &Memory) -> Option<[u8; 4]> {
        let (offset_idx, length_idx) = match opcode {
            OP_CALL | OP_CALLCODE => (3, 4),
            OP_DELEGATECALL | OP_STATICCALL => (2, 3),
            _ => return None,
        };

        let args_offset = stack.peek(offset_idx)?.as_usize();
        let args_length = stack.peek(length_idx)?.as_usize();

        if args_length < 4 {
            return None;
        }

        let buf = memory.buffer.borrow();
        let base = memory.current_base_offset();
        let start = base + args_offset;
        let end = start + 4;

        if end <= buf.len() {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&buf[start..end]);
            Some(selector)
        } else {
            None
        }
    }

    /// Extract storage write info for SSTORE from pre-execution stack.
    fn extract_sstore(
        opcode: u8,
        stack: &Stack,
        code_address: Address,
    ) -> Option<Vec<StorageWrite>> {
        if opcode != OP_SSTORE {
            return None;
        }
        // SSTORE stack: [key, value]
        let key = stack.peek(0)?;
        let new_value = stack.peek(1)?;
        let slot = H256::from(key.to_big_endian());
        Some(vec![StorageWrite {
            address: code_address,
            slot,
            old_value: U256::zero(), // Filled post-hoc by enrichment
            new_value,
        }])
    }
}

impl OpcodeRecorder for DebugRecorder {
    #[allow(clippy::too_many_arguments)]
    fn record_step(
        &mut self,
        opcode: u8,
        pc: usize,
        gas_remaining: i64,
        depth: usize,
        stack: &Stack,
        memory: &Memory,
        code_address: Address,
    ) {
        let step_index = self.steps.len();
        let stack_top = self.capture_stack_top(stack);
        let stack_depth = stack.len();
        let memory_size = memory.len();

        let call_value = Self::extract_call_value(opcode, stack);
        let log_topics = Self::extract_log_topics(opcode, stack);
        let log_data = Self::extract_log_data(opcode, stack, memory);
        let storage_writes = Self::extract_sstore(opcode, stack, code_address);
        let call_input_selector = Self::extract_call_input_selector(opcode, stack, memory);

        self.steps.push(StepRecord {
            step_index,
            pc,
            opcode,
            depth,
            gas_remaining,
            stack_top,
            stack_depth,
            memory_size,
            code_address,
            call_value,
            storage_writes,
            log_topics,
            log_data,
            call_input_selector,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK_LIMIT: usize = 1024;

    /// Build a Stack with values placed so peek(0..N) returns them in order.
    fn make_stack(values: &[U256]) -> Stack {
        let mut stack = Stack {
            values: Box::new([U256::zero(); STACK_LIMIT]),
            offset: STACK_LIMIT,
        };
        // Push in reverse so peek(0) = values[0], peek(1) = values[1], etc.
        for v in values.iter().rev() {
            stack.push(*v).unwrap();
        }
        stack
    }

    /// Build a Memory with given bytes starting at offset 0.
    fn make_memory(bytes: &[u8]) -> Memory {
        let mem = Memory::new();
        mem.buffer.borrow_mut().extend_from_slice(bytes);
        mem
    }

    #[test]
    fn call_input_selector_extracted_for_call() {
        // CALL stack: [gas, to, value, argsOffset, argsLength, retOffset, retLength]
        let stack = make_stack(&[
            U256::from(50_000_u64), // gas
            U256::from(0xBB_u64),   // to
            U256::zero(),           // value
            U256::from(0_u64),      // argsOffset = 0
            U256::from(36_u64),     // argsLength = 36 (>= 4)
            U256::zero(),           // retOffset
            U256::from(32_u64),     // retLength
        ]);
        let memory = make_memory(&[0xa9, 0x05, 0x9c, 0xbb, 0x00, 0x00]);

        let result = DebugRecorder::extract_call_input_selector(OP_CALL, &stack, &memory);
        assert_eq!(result, Some([0xa9, 0x05, 0x9c, 0xbb]));
    }

    #[test]
    fn call_input_selector_extracted_for_delegatecall() {
        // DELEGATECALL stack: [gas, to, argsOffset, argsLength, retOffset, retLength]
        let stack = make_stack(&[
            U256::from(50_000_u64), // gas
            U256::from(0xDD_u64),   // to
            U256::from(0_u64),      // argsOffset = 0
            U256::from(68_u64),     // argsLength = 68 (>= 4)
            U256::zero(),           // retOffset
            U256::from(32_u64),     // retLength
        ]);
        let memory = make_memory(&[0x12, 0x34, 0x56, 0x78, 0x00]);

        let result = DebugRecorder::extract_call_input_selector(OP_DELEGATECALL, &stack, &memory);
        assert_eq!(result, Some([0x12, 0x34, 0x56, 0x78]));
    }

    #[test]
    fn call_input_selector_extracted_for_staticcall() {
        // STATICCALL stack: same layout as DELEGATECALL
        let stack = make_stack(&[
            U256::from(30_000_u64),
            U256::from(0xEE_u64),
            U256::from(0_u64), // argsOffset
            U256::from(4_u64), // argsLength = exactly 4
            U256::zero(),
            U256::from(32_u64),
        ]);
        let memory = make_memory(&[0xde, 0xad, 0xbe, 0xef]);

        let result = DebugRecorder::extract_call_input_selector(OP_STATICCALL, &stack, &memory);
        assert_eq!(result, Some([0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn call_input_selector_none_for_short_calldata() {
        // argsLength = 3 (< 4)
        let stack = make_stack(&[
            U256::from(50_000_u64),
            U256::from(0xBB_u64),
            U256::zero(),
            U256::from(0_u64), // argsOffset
            U256::from(3_u64), // argsLength < 4
            U256::zero(),
            U256::from(32_u64),
        ]);
        let memory = make_memory(&[0xaa, 0xbb, 0xcc]);

        let result = DebugRecorder::extract_call_input_selector(OP_CALL, &stack, &memory);
        assert!(result.is_none());
    }

    #[test]
    fn call_input_selector_none_for_non_call_opcode() {
        let stack = make_stack(&[U256::from(42_u64)]);
        let memory = make_memory(&[0xaa, 0xbb, 0xcc, 0xdd]);

        // ADD opcode (0x01)
        let result = DebugRecorder::extract_call_input_selector(0x01, &stack, &memory);
        assert!(result.is_none());
    }

    #[test]
    fn call_input_selector_none_when_memory_too_short() {
        // argsOffset = 10, argsLength = 4, but memory only has 8 bytes
        let stack = make_stack(&[
            U256::from(50_000_u64),
            U256::from(0xBB_u64),
            U256::zero(),
            U256::from(10_u64), // argsOffset = 10
            U256::from(4_u64),  // argsLength = 4
            U256::zero(),
            U256::from(32_u64),
        ]);
        let memory = make_memory(&[0u8; 8]); // only 8 bytes, need offset 10+4=14

        let result = DebugRecorder::extract_call_input_selector(OP_CALL, &stack, &memory);
        assert!(result.is_none());
    }

    #[test]
    fn call_input_selector_with_nonzero_offset() {
        // Selector is at argsOffset=4 in memory
        let stack = make_stack(&[
            U256::from(50_000_u64),
            U256::from(0xBB_u64),
            U256::zero(),
            U256::from(4_u64),  // argsOffset = 4
            U256::from(36_u64), // argsLength = 36
            U256::zero(),
            U256::from(32_u64),
        ]);
        let memory = make_memory(&[0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe, 0x11, 0x22]);

        let result = DebugRecorder::extract_call_input_selector(OP_CALL, &stack, &memory);
        assert_eq!(result, Some([0xca, 0xfe, 0xba, 0xbe]));
    }
}
