//! Fund flow tracer for ETH and ERC-20 transfers.
//!
//! Extracts value transfers from the execution trace by detecting:
//! - ETH transfers via CALL with value > 0
//! - ERC-20 transfers via LOG3 with Transfer(address,address,uint256) topic

use ethrex_common::{Address, H256, U256};

use crate::opcodes::{OP_CALL, OP_CALLCODE, OP_CREATE, OP_CREATE2, OP_LOG3};
use crate::types::StepRecord;

use super::rpc_client::RpcLog;
use super::types::FundFlow;

/// keccak256("Transfer(address,address,uint256)") — full 32-byte topic.
const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// keccak256("Transfer(address,address,uint256)") first 4 bytes = 0xddf252ad
const TRANSFER_TOPIC_PREFIX: [u8; 4] = [0xdd, 0xf2, 0x52, 0xad];

/// Stateless fund flow tracer.
pub struct FundFlowTracer;

impl FundFlowTracer {
    /// Trace all fund flows (ETH + ERC-20) in the execution trace.
    pub fn trace(steps: &[StepRecord]) -> Vec<FundFlow> {
        let mut flows = Vec::new();
        flows.extend(Self::trace_eth_transfers(steps));
        flows.extend(Self::trace_erc20_transfers(steps));
        // Sort by step index for chronological order
        flows.sort_by_key(|f| f.step_index);
        flows
    }

    /// Trace native ETH transfers (CALL with value > 0).
    fn trace_eth_transfers(steps: &[StepRecord]) -> Vec<FundFlow> {
        steps
            .iter()
            .filter(|s| matches!(s.opcode, OP_CALL | OP_CALLCODE | OP_CREATE | OP_CREATE2))
            .filter_map(|s| {
                let value = s.call_value.as_ref()?;
                if *value == U256::zero() {
                    return None;
                }
                let (from, to) = extract_eth_transfer_parties(s)?;
                Some(FundFlow {
                    from,
                    to,
                    value: *value,
                    token: None,
                    step_index: s.step_index,
                })
            })
            .collect()
    }

    /// Trace ERC-20 Transfer events from receipt logs.
    ///
    /// This is the fallback path used when LEVM reverts (so LOG opcodes never
    /// executed) but the on-chain receipt shows success. Receipt logs contain
    /// the same Transfer events that would have been captured by opcode tracing.
    ///
    /// Each resulting `FundFlow` has `step_index = usize::MAX` to indicate it
    /// came from receipt data rather than opcode-level tracing.
    pub fn trace_from_receipt_logs(logs: &[RpcLog]) -> Vec<FundFlow> {
        logs.iter()
            .filter_map(|log| {
                if log.topics.len() < 3 {
                    return None;
                }

                // Check full Transfer topic signature
                if log.topics[0].as_bytes() != TRANSFER_TOPIC {
                    return None;
                }

                let from = address_from_topic(&log.topics[1]);
                let to = address_from_topic(&log.topics[2]);
                let token = log.address;

                let value = if log.data.len() >= 32 {
                    U256::from_big_endian(&log.data[..32])
                } else {
                    U256::zero()
                };

                Some(FundFlow {
                    from,
                    to,
                    value,
                    token: Some(token),
                    step_index: usize::MAX,
                })
            })
            .collect()
    }

    /// Trace ERC-20 transfers (LOG3 with Transfer topic).
    fn trace_erc20_transfers(steps: &[StepRecord]) -> Vec<FundFlow> {
        steps
            .iter()
            .filter(|s| s.opcode == OP_LOG3)
            .filter_map(|s| {
                let topics = s.log_topics.as_ref()?;
                if topics.len() < 3 {
                    return None;
                }

                // Check Transfer topic signature
                let sig = topics[0];
                if sig.as_bytes()[..4] != TRANSFER_TOPIC_PREFIX {
                    return None;
                }

                // topic[1] = from address (left-padded to 32 bytes)
                let from = address_from_topic(&topics[1]);
                // topic[2] = to address
                let to = address_from_topic(&topics[2]);

                // Token contract = the contract emitting the log
                let token = s.code_address;

                // Decode amount from log data (ABI-encoded uint256 in first 32 bytes)
                let value = s
                    .log_data
                    .as_ref()
                    .filter(|d| d.len() >= 32)
                    .map(|d| U256::from_big_endian(&d[..32]))
                    .unwrap_or(U256::zero());

                Some(FundFlow {
                    from,
                    to,
                    value,
                    token: Some(token),
                    step_index: s.step_index,
                })
            })
            .collect()
    }
}

/// Extract from/to for ETH transfers from CALL-family opcodes.
fn extract_eth_transfer_parties(step: &StepRecord) -> Option<(Address, Address)> {
    let from = step.code_address;
    match step.opcode {
        OP_CALL | OP_CALLCODE => {
            // stack[1] = to address
            let to_val = step.stack_top.get(1)?;
            let bytes = to_val.to_big_endian();
            let to = Address::from_slice(&bytes[12..]);
            Some((from, to))
        }
        OP_CREATE | OP_CREATE2 => {
            // CREATE target address not known pre-execution
            Some((from, Address::zero()))
        }
        _ => None,
    }
}

/// Extract an address from a 32-byte topic (last 20 bytes).
fn address_from_topic(topic: &H256) -> Address {
    Address::from_slice(&topic.as_bytes()[12..])
}
