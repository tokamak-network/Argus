//! Fund flow tracer for ETH and ERC-20 transfers.
//!
//! Extracts value transfers from the execution trace by detecting:
//! - ETH transfers via CALL with value > 0
//! - ERC-20 transfers via LOG3 with Transfer(address,address,uint256) topic

use ethrex_common::{Address, H256, U256};

use crate::types::StepRecord;

use super::types::FundFlow;

// Opcode constants
const OP_CALL: u8 = 0xF1;
const OP_CALLCODE: u8 = 0xF2;
const OP_CREATE: u8 = 0xF0;
const OP_CREATE2: u8 = 0xF5;
const OP_LOG3: u8 = 0xA3;

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
