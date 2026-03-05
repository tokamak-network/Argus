//! Context Extractor: converts opcode-level `StepRecord` traces into structured `AgentContext`.
//!
//! Like a crime scene investigator turning raw evidence (fingerprints, footprints, CCTV frames)
//! into a structured report. Each opcode step is a "frame" — we extract meaningful patterns
//! (calls, storage writes, token transfers) from the raw execution trace.

use ethrex_common::{Address, H256, U256};

use super::types::{
    AgentContext, CallFrame, CallType, ContractCreation, CreateType, DelegateCallInfo, EthTransfer,
    LogEvent, StorageMutation, TokenTransfer,
};
use crate::types::StepRecord;

// ── ExtractParams ────────────────────────────────────────────────────────

/// Transaction metadata passed to [`ContextExtractor::extract`].
///
/// Groups the externally-provided fields (from pre-filter / RPC) so the
/// extractor signature stays manageable as new metadata is added.
pub struct ExtractParams {
    pub tx_hash: H256,
    pub block_number: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub value_wei: U256,
    pub gas_used: u64,
    pub succeeded: bool,
    pub suspicious_score: f64,
    pub suspicion_reasons: Vec<String>,
}

// ── Opcode constants ───────────────────────────────────────────────────────

const OP_SSTORE: u8 = 0x55;
const OP_CALL: u8 = 0xF1;
const OP_CALLCODE: u8 = 0xF2;
const OP_DELEGATECALL: u8 = 0xF4;
const OP_CREATE: u8 = 0xF0;
const OP_CREATE2: u8 = 0xF5;
const OP_STATICCALL: u8 = 0xFA;
const OP_REVERT: u8 = 0xFD;
const OP_LOG0: u8 = 0xA0;
const OP_LOG4: u8 = 0xA4;

/// ERC-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
const TRANSFER_TOPIC: H256 = H256([
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
]);

// ── ContextExtractor ───────────────────────────────────────────────────────

/// Extracts structured `AgentContext` from a raw opcode trace.
pub struct ContextExtractor;

impl ContextExtractor {
    /// Extract an `AgentContext` from a sequence of `StepRecord`s.
    ///
    /// Transaction metadata is provided via [`ExtractParams`]; the extractor
    /// populates the trace-derived fields (call_graph, storage_mutations, etc.).
    pub fn extract(steps: &[StepRecord], params: ExtractParams) -> AgentContext {
        let call_graph = Self::extract_call_graph(steps, params.from);
        let storage_mutations = Self::extract_storage_mutations(steps);
        let (erc20_transfers, log_events) = Self::extract_logs(steps);
        let eth_transfers = Self::extract_eth_transfers(steps);
        let revert_count = Self::count_reverts(steps);
        let delegatecalls = Self::extract_delegatecalls(steps);
        let contract_creations = Self::extract_contract_creations(steps);

        AgentContext {
            tx_hash: params.tx_hash,
            block_number: params.block_number,
            from: params.from,
            to: params.to,
            value_wei: params.value_wei,
            gas_used: params.gas_used,
            succeeded: params.succeeded,
            revert_count,
            suspicious_score: params.suspicious_score,
            suspicion_reasons: params.suspicion_reasons,
            call_graph,
            storage_mutations,
            erc20_transfers,
            eth_transfers,
            log_events,
            delegatecalls,
            contract_creations,
        }
    }

    /// Extract call graph from CALL/STATICCALL/DELEGATECALL/CALLCODE opcodes.
    fn extract_call_graph(steps: &[StepRecord], tx_from: Address) -> Vec<CallFrame> {
        let call_meta = Self::precompute_call_meta(steps);
        let mut frames = Vec::new();

        for (i, step) in steps.iter().enumerate() {
            let call_type = match step.opcode {
                OP_CALL => CallType::Call,
                OP_STATICCALL => CallType::StaticCall,
                OP_DELEGATECALL => CallType::DelegateCall,
                OP_CALLCODE => CallType::CallCode,
                _ => continue,
            };

            let target = Self::extract_call_target(step);
            let value = step.call_value.unwrap_or(U256::zero());
            let input_selector = Self::extract_input_selector(step);
            let (input_size, output_size) = Self::extract_call_sizes(step);

            let (gas_used, reverted) = call_meta.get(&i).copied().unwrap_or((0, false));

            frames.push(CallFrame {
                depth: step.depth as u16,
                caller: step.code_address,
                target,
                value,
                input_selector,
                input_size,
                output_size,
                gas_used,
                call_type,
                reverted,
            });
        }

        // For the root call (depth 0), replace caller with tx_from (immutable)
        match frames.as_slice() {
            [first, ..] if first.depth == 0 => {
                let patched = CallFrame {
                    caller: tx_from,
                    ..first.clone()
                };
                let mut result = vec![patched];
                result.extend_from_slice(&frames[1..]);
                result
            }
            _ => frames,
        }
    }

    /// Extract the target address from a CALL-family opcode's stack.
    fn extract_call_target(step: &StepRecord) -> Address {
        // CALL/CALLCODE: stack[1] = to address
        // DELEGATECALL/STATICCALL: stack[1] = to address
        let addr_val = match step.opcode {
            OP_CALL | OP_CALLCODE => step.stack_top.get(1),
            OP_DELEGATECALL | OP_STATICCALL => step.stack_top.get(1),
            _ => None,
        };

        match addr_val {
            Some(val) => {
                let bytes = val.to_big_endian();
                Address::from_slice(&bytes[12..32])
            }
            None => Address::zero(),
        }
    }

    /// Extract the 4-byte function selector from CALL input data.
    /// For CALL/CALLCODE: stack[3]=argsOffset, stack[4]=argsLength
    /// For DELEGATECALL/STATICCALL: stack[2]=argsOffset, stack[3]=argsLength
    fn extract_input_selector(step: &StepRecord) -> Option<[u8; 4]> {
        let args_length_idx = match step.opcode {
            OP_CALL | OP_CALLCODE => 4,
            OP_DELEGATECALL | OP_STATICCALL => 3,
            _ => return None,
        };

        // Check that input length >= 4 bytes
        let args_len = step.stack_top.get(args_length_idx)?;
        if args_len.as_usize() < 4 {
            return None;
        }

        // We don't have access to memory here, but we can't extract the selector
        // from the stack alone. We'll use a placeholder approach:
        // The actual selector extraction would require memory access.
        // For now, return None. The recorder.rs already captures log_data for LOGs
        // but not call input data. This is a known limitation.
        //
        // TODO(phase2): Add calldata capture to DebugRecorder for selector extraction.
        None
    }

    /// Extract input/output sizes from the call stack.
    fn extract_call_sizes(step: &StepRecord) -> (usize, usize) {
        match step.opcode {
            // CALL/CALLCODE: stack = [gas, to, value, argsOffset, argsLength, retOffset, retLength]
            OP_CALL | OP_CALLCODE => {
                let input = step.stack_top.get(4).map(|v| v.as_usize()).unwrap_or(0);
                let output = step.stack_top.get(6).map(|v| v.as_usize()).unwrap_or(0);
                (input, output)
            }
            // DELEGATECALL/STATICCALL: stack = [gas, to, argsOffset, argsLength, retOffset, retLength]
            OP_DELEGATECALL | OP_STATICCALL => {
                let input = step.stack_top.get(3).map(|v| v.as_usize()).unwrap_or(0);
                let output = step.stack_top.get(5).map(|v| v.as_usize()).unwrap_or(0);
                (input, output)
            }
            _ => (0, 0),
        }
    }

    /// Pre-compute (gas_used, reverted) for every CALL-family opcode in one O(n) pass.
    ///
    /// Uses a depth stack: when a step returns to or below a pending call's depth,
    /// that call is resolved. This replaces the previous O(n×m) forward-scan approach.
    fn precompute_call_meta(steps: &[StepRecord]) -> std::collections::HashMap<usize, (u64, bool)> {
        let mut result = std::collections::HashMap::new();
        // Stack entries: (call_step_index, call_depth, saw_revert_at_depth_plus_one)
        let mut stack: Vec<(usize, usize, bool)> = Vec::new();

        for (i, step) in steps.iter().enumerate() {
            // Pop completed calls whose depth >= current step's depth
            while let Some(&(call_idx, call_depth, saw_revert)) = stack.last() {
                if step.depth <= call_depth {
                    let gas_used = if step.depth == call_depth {
                        let before = steps[call_idx].gas_remaining;
                        before.saturating_sub(step.gas_remaining).max(0) as u64
                    } else {
                        0 // Jumped past this depth (abnormal) — no accurate measurement
                    };
                    result.insert(call_idx, (gas_used, saw_revert));
                    stack.pop();
                } else {
                    break;
                }
            }

            // Track REVERT at exactly call_depth + 1
            if step.opcode == OP_REVERT
                && let Some(top) = stack.last_mut()
                && step.depth == top.1 + 1
            {
                top.2 = true;
            }

            // Push new CALL-family opcodes
            if matches!(
                step.opcode,
                OP_CALL | OP_STATICCALL | OP_DELEGATECALL | OP_CALLCODE
            ) {
                stack.push((i, step.depth, false));
            }
        }

        // Remaining calls that never returned (end of trace)
        for (call_idx, _, saw_revert) in stack {
            result.insert(call_idx, (0, saw_revert));
        }

        result
    }

    /// Extract storage mutations from SSTORE opcodes.
    fn extract_storage_mutations(steps: &[StepRecord]) -> Vec<StorageMutation> {
        let mut mutations = Vec::new();

        // Track "callback" heuristic: if we see SSTORE at depth > initial SSTORE depth
        // after a CALL back to the same contract, it's a potential reentrancy indicator.
        let mut first_sstore_depth: Option<usize> = None;

        for step in steps {
            if step.opcode != OP_SSTORE {
                continue;
            }

            if let Some(writes) = &step.storage_writes {
                for write in writes {
                    let in_callback = match first_sstore_depth {
                        Some(d) => step.depth > d,
                        None => {
                            first_sstore_depth = Some(step.depth);
                            false
                        }
                    };

                    let old_value_h256 = H256::from(write.old_value.to_big_endian());
                    let new_value_h256 = H256::from(write.new_value.to_big_endian());

                    mutations.push(StorageMutation {
                        contract: write.address,
                        slot: write.slot,
                        old_value: old_value_h256,
                        new_value: new_value_h256,
                        in_callback,
                    });
                }
            }
        }

        mutations
    }

    /// Extract ERC-20 transfers (LOG3 with Transfer topic) and other log events.
    fn extract_logs(steps: &[StepRecord]) -> (Vec<TokenTransfer>, Vec<LogEvent>) {
        let mut erc20_transfers = Vec::new();
        let mut log_events = Vec::new();

        for step in steps {
            if !(OP_LOG0..=OP_LOG4).contains(&step.opcode) {
                continue;
            }

            let topics = match &step.log_topics {
                Some(t) => t,
                None => continue,
            };

            let topic_count = (step.opcode - OP_LOG0) as usize;

            // LOG3 with Transfer topic → ERC-20 transfer
            if topic_count == 3 && topics.first() == Some(&TRANSFER_TOPIC) {
                let token = step.code_address;
                let from_addr = Self::h256_to_address(topics.get(1));
                let to_addr = Self::h256_to_address(topics.get(2));
                let amount = Self::extract_transfer_amount(step);

                erc20_transfers.push(TokenTransfer {
                    token,
                    from: from_addr,
                    to: to_addr,
                    amount,
                });
            } else if let Some(topic0) = topics.first() {
                // Non-Transfer log event
                let data_size = step.log_data.as_ref().map(|d| d.len()).unwrap_or(0);

                log_events.push(LogEvent {
                    address: step.code_address,
                    topic0: *topic0,
                    topics: topics.iter().skip(1).copied().collect(),
                    data_size,
                });
            }
        }

        (erc20_transfers, log_events)
    }

    /// Extract ETH transfers from CALL opcodes with non-zero value.
    fn extract_eth_transfers(steps: &[StepRecord]) -> Vec<EthTransfer> {
        let mut transfers = Vec::new();

        for step in steps {
            // Only CALL and CALLCODE transfer ETH value
            if !matches!(step.opcode, OP_CALL | OP_CALLCODE) {
                continue;
            }

            let value = match step.call_value {
                Some(v) if v > U256::zero() => v,
                _ => continue,
            };

            let target = Self::extract_call_target(step);

            transfers.push(EthTransfer {
                from: step.code_address,
                to: target,
                value,
                call_depth: step.depth as u16,
            });
        }

        transfers
    }

    /// Count REVERT opcodes in the trace.
    fn count_reverts(steps: &[StepRecord]) -> u32 {
        steps.iter().filter(|s| s.opcode == OP_REVERT).count() as u32
    }

    /// Extract DELEGATECALL info from the trace.
    fn extract_delegatecalls(steps: &[StepRecord]) -> Vec<DelegateCallInfo> {
        steps
            .iter()
            .filter(|s| s.opcode == OP_DELEGATECALL)
            .map(|step| {
                let target = Self::extract_call_target(step);
                DelegateCallInfo {
                    caller: step.code_address,
                    target,
                    input_selector: Self::extract_input_selector(step),
                }
            })
            .collect()
    }

    /// Extract contract creations (CREATE/CREATE2).
    fn extract_contract_creations(steps: &[StepRecord]) -> Vec<ContractCreation> {
        let mut creations = Vec::new();

        for step in steps {
            let create_type = match step.opcode {
                OP_CREATE => CreateType::Create,
                OP_CREATE2 => CreateType::Create2,
                _ => continue,
            };

            // For CREATE/CREATE2, the deployed address is not directly on the stack
            // pre-execution. It's the return value. We can't get it from pre-execution state.
            // Use Address::zero() as placeholder — enrichment can fill this later.
            creations.push(ContractCreation {
                deployer: step.code_address,
                deployed: Address::zero(), // Not available pre-execution
                code_size: Self::extract_create_code_size(step),
                create_type,
            });
        }

        creations
    }

    /// Extract code size from CREATE/CREATE2 stack.
    /// CREATE: stack = [value, offset, length]
    /// CREATE2: stack = [value, offset, length, salt]
    fn extract_create_code_size(step: &StepRecord) -> usize {
        step.stack_top.get(2).map(|v| v.as_usize()).unwrap_or(0)
    }

    /// Convert an H256 topic to an Address (last 20 bytes).
    fn h256_to_address(topic: Option<&H256>) -> Address {
        match topic {
            Some(h) => Address::from_slice(&h.as_bytes()[12..32]),
            None => Address::zero(),
        }
    }

    /// Extract ERC-20 transfer amount from LOG data.
    fn extract_transfer_amount(step: &StepRecord) -> U256 {
        match &step.log_data {
            Some(data) if data.len() >= 32 => {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&data[..32]);
                U256::from_big_endian(&bytes)
            }
            _ => U256::zero(),
        }
    }
}
