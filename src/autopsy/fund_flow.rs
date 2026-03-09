//! Fund flow tracer for ETH and ERC-20 transfers.
//!
//! Extracts value transfers from the execution trace by detecting:
//! - ETH transfers via CALL with value > 0
//! - ERC-20 transfers via LOG3 with Transfer(address,address,uint256) topic

use ethrex_common::{Address, H256, U256};

use crate::opcodes::{OP_CALL, OP_CALLCODE, OP_CREATE, OP_CREATE2, OP_LOG3};
use crate::types::{EventType, StepRecord};

use super::rpc_client::RpcLog;
use super::types::FundFlow;

/// keccak256("Transfer(address,address,uint256)") — full 32-byte topic.
const TRANSFER_TOPIC: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
    0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

/// keccak256("Transfer(address,address,uint256)") first 4 bytes = 0xddf252ad
const TRANSFER_TOPIC_PREFIX: [u8; 4] = [0xdd, 0xf2, 0x52, 0xad];

/// keccak256("Swap(address,uint256,uint256,uint256,uint256,address)") — Uniswap V2
const SWAP_V2_TOPIC: [u8; 32] = [
    0xd7, 0x8a, 0xd9, 0x5f, 0xa4, 0x6c, 0x99, 0x4b, 0x65, 0x51, 0xd0, 0xda, 0x85, 0xfc, 0x27, 0x5f,
    0xe6, 0x13, 0xce, 0x37, 0x65, 0x7f, 0xb8, 0xd5, 0xe3, 0xd1, 0x30, 0x84, 0x01, 0x59, 0xd8, 0x22,
];

/// keccak256("Swap(address,address,int256,int256,uint160,uint128,int24)") — Uniswap V3
const SWAP_V3_TOPIC: [u8; 32] = [
    0xc4, 0x20, 0x79, 0xf9, 0x4a, 0x63, 0x50, 0xd7, 0xe6, 0x23, 0x5f, 0x29, 0x17, 0x49, 0x24, 0xf9,
    0x28, 0xcc, 0x2a, 0xc8, 0x18, 0xeb, 0x64, 0xfe, 0xd8, 0x00, 0x4e, 0x11, 0x5f, 0xbc, 0xca, 0x67,
];

/// keccak256("LiquidationCall(address,address,address,uint256,uint256,address,bool)") — Aave V3
const LIQUIDATION_CALL_TOPIC: [u8; 32] = [
    0xe4, 0x13, 0xa3, 0x21, 0xe8, 0x68, 0x1d, 0x83, 0x1f, 0x4d, 0xbc, 0xcb, 0xca, 0x79, 0x0d, 0x29,
    0x52, 0xb5, 0x6f, 0x97, 0x79, 0x08, 0xe4, 0x5b, 0xe3, 0x73, 0x35, 0x53, 0x3e, 0x00, 0x52, 0x86,
];

/// keccak256("LiquidateBorrow(address,address,uint256,address,uint256)") — Compound
const LIQUIDATE_BORROW_TOPIC: [u8; 32] = [
    0x29, 0x86, 0x37, 0xf6, 0x84, 0xda, 0x70, 0x67, 0x4f, 0x26, 0x50, 0x9b, 0x10, 0xf0, 0x7e, 0xc2,
    0xfb, 0xc7, 0x7a, 0x33, 0x5a, 0xb1, 0xe7, 0xd6, 0x21, 0x5a, 0x4b, 0x24, 0x84, 0xd8, 0xbb, 0x52,
];

/// Classify a log event by matching the first topic against known DeFi event signatures.
pub fn classify_log_event(topics: &[[u8; 32]]) -> EventType {
    if topics.is_empty() {
        return EventType::Unknown;
    }
    match topics[0] {
        t if t == TRANSFER_TOPIC => EventType::Transfer,
        t if t == SWAP_V2_TOPIC => EventType::Swap,
        t if t == SWAP_V3_TOPIC => EventType::Swap,
        t if t == LIQUIDATION_CALL_TOPIC => EventType::LiquidationCall,
        t if t == LIQUIDATE_BORROW_TOPIC => EventType::LiquidateBorrow,
        _ => EventType::Unknown,
    }
}

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
                    event_type: EventType::Transfer,
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

                // Classify the event from the topic hash
                let topic_bytes: Vec<[u8; 32]> = log
                    .topics
                    .iter()
                    .map(|t| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(t.as_bytes());
                        arr
                    })
                    .collect();
                let event_type = classify_log_event(&topic_bytes);

                Some(FundFlow {
                    from,
                    to,
                    value,
                    token: Some(token),
                    step_index: usize::MAX,
                    event_type,
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
                    event_type: EventType::Transfer,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_empty_topics_returns_unknown() {
        assert_eq!(classify_log_event(&[]), EventType::Unknown);
    }

    #[test]
    fn test_classify_transfer_topic() {
        assert_eq!(classify_log_event(&[TRANSFER_TOPIC]), EventType::Transfer);
    }

    #[test]
    fn test_classify_swap_v2_topic() {
        assert_eq!(classify_log_event(&[SWAP_V2_TOPIC]), EventType::Swap);
    }

    #[test]
    fn test_classify_swap_v3_topic() {
        assert_eq!(classify_log_event(&[SWAP_V3_TOPIC]), EventType::Swap);
    }

    #[test]
    fn test_classify_liquidation_call_topic() {
        assert_eq!(
            classify_log_event(&[LIQUIDATION_CALL_TOPIC]),
            EventType::LiquidationCall,
        );
    }

    #[test]
    fn test_classify_liquidate_borrow_topic() {
        assert_eq!(
            classify_log_event(&[LIQUIDATE_BORROW_TOPIC]),
            EventType::LiquidateBorrow,
        );
    }

    #[test]
    fn test_classify_unknown_topic() {
        let random_topic = [0xab; 32];
        assert_eq!(classify_log_event(&[random_topic]), EventType::Unknown);
    }

    #[test]
    fn test_classify_uses_first_topic_only() {
        // First topic is Swap V2; remaining topics irrelevant.
        assert_eq!(
            classify_log_event(&[SWAP_V2_TOPIC, TRANSFER_TOPIC, LIQUIDATION_CALL_TOPIC]),
            EventType::Swap,
        );
    }

    #[test]
    fn test_classify_transfer_with_extra_topics() {
        let addr_topic = [0x00u8; 32]; // zero-padded address topic
        assert_eq!(
            classify_log_event(&[TRANSFER_TOPIC, addr_topic, addr_topic]),
            EventType::Transfer,
        );
    }

    #[test]
    fn test_event_type_default_is_unknown() {
        assert_eq!(EventType::default(), EventType::Unknown);
    }
}
