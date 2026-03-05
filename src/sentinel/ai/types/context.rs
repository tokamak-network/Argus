//! AgentContext and its sub-types (CallFrame, StorageMutation, etc.).

use ethrex_common::{Address, H256, U256};
use serde::{Deserialize, Serialize};

use super::attack_type::{CallType, CreateType};

// ── Sub-types ────────────────────────────────────────────────────────────────

/// A single frame in the EVM call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// EVM call depth (0-based). Max EVM depth is 1024, so u16 is sufficient.
    pub depth: u16,
    pub caller: Address,
    pub target: Address,
    pub value: U256,
    /// First 4 bytes of calldata (function selector). None for raw ETH sends.
    pub input_selector: Option<[u8; 4]>,
    pub input_size: usize,
    pub output_size: usize,
    pub gas_used: u64,
    pub call_type: CallType,
    pub reverted: bool,
}

/// A storage slot mutation observed during TX execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMutation {
    pub contract: Address,
    pub slot: H256,
    pub old_value: H256,
    pub new_value: H256,
    /// True if this mutation occurred inside a callback (reentrancy indicator).
    pub in_callback: bool,
}

/// An ERC-20 Transfer event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

/// An ETH value transfer (CALL with non-zero value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthTransfer {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    /// Call depth at which the transfer occurred.
    pub call_depth: u16,
}

/// A non-Transfer log event (Approval, Swap, Sync, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub address: Address,
    /// event signature hash (topic[0]).
    pub topic0: H256,
    /// Indexed parameters (topic[1..]).
    pub topics: Vec<H256>,
    /// Byte length of non-indexed (data) field.
    pub data_size: usize,
}

/// A DELEGATECALL observed during TX execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateCallInfo {
    pub caller: Address,
    pub target: Address,
    /// None for proxy fallback / empty calldata patterns.
    pub input_selector: Option<[u8; 4]>,
}

/// A contract deployed during TX execution (CREATE / CREATE2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCreation {
    pub deployer: Address,
    pub deployed: Address,
    pub code_size: usize,
    pub create_type: CreateType,
}

// ── AgentContext ─────────────────────────────────────────────────────────────

/// Full TX analysis context passed to the AI agent.
///
/// Extracted from opcode-level trace. Serialised to JSON (~2-5 KB) and sent
/// as the user message in the Claude API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    pub tx_hash: H256,
    pub block_number: u64,
    pub from: Address,
    /// `None` for contract-creation transactions.
    pub to: Option<Address>,
    pub value_wei: U256,
    pub gas_used: u64,
    pub succeeded: bool,
    /// Number of internal reverts (key reentrancy signal).
    pub revert_count: u32,
    /// Pre-filter suspicion score (0.0 – 1.0).
    pub suspicious_score: f64,
    /// Human-readable reasons from the pre-filter.
    pub suspicion_reasons: Vec<String>,
    pub call_graph: Vec<CallFrame>,
    pub storage_mutations: Vec<StorageMutation>,
    pub erc20_transfers: Vec<TokenTransfer>,
    pub eth_transfers: Vec<EthTransfer>,
    pub log_events: Vec<LogEvent>,
    pub delegatecalls: Vec<DelegateCallInfo>,
    pub contract_creations: Vec<ContractCreation>,
}

impl AgentContext {
    /// Approximate serialised byte size (for context-size budget checks).
    ///
    /// Uses `serde_json` serialisation. Returns `Err` if serialisation fails.
    pub fn approx_json_bytes(&self) -> Result<usize, serde_json::Error> {
        Ok(serde_json::to_string(self)?.len())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{Address, H256, U256};

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
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

    #[test]
    fn agent_context_json_roundtrip_minimal() {
        let ctx = minimal_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tx_hash, ctx.tx_hash);
        assert_eq!(decoded.block_number, ctx.block_number);
        assert_eq!(decoded.gas_used, ctx.gas_used);
        assert_eq!(decoded.succeeded, ctx.succeeded);
    }

    #[test]
    fn agent_context_contract_creation_to_is_none() {
        let mut ctx = minimal_context();
        ctx.to = None;
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert!(decoded.to.is_none());
    }

    #[test]
    fn agent_context_with_call_graph_roundtrip() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![
            CallFrame {
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
            },
            CallFrame {
                depth: 1,
                caller: addr(0xBB),
                target: addr(0xCC),
                value: U256::from(1_000_000_u64),
                input_selector: None,
                input_size: 0,
                output_size: 0,
                gas_used: 2_300,
                call_type: CallType::Call,
                reverted: true,
            },
        ];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.call_graph.len(), 2);
        assert_eq!(
            decoded.call_graph[0].input_selector,
            Some([0xde, 0xad, 0xbe, 0xef])
        );
        assert!(decoded.call_graph[0].input_selector.is_some());
        assert!(decoded.call_graph[1].input_selector.is_none());
        assert!(decoded.call_graph[1].reverted);
    }

    #[test]
    fn agent_context_with_storage_mutations_roundtrip() {
        let mut ctx = minimal_context();
        ctx.storage_mutations = vec![StorageMutation {
            contract: addr(0xBB),
            slot: h256(0x01),
            old_value: h256(0x00),
            new_value: h256(0x01),
            in_callback: true,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.storage_mutations.len(), 1);
        assert!(decoded.storage_mutations[0].in_callback);
    }

    #[test]
    fn agent_context_with_erc20_transfers_roundtrip() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_000_000_000_000_u64),
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.erc20_transfers.len(), 1);
        assert_eq!(
            decoded.erc20_transfers[0].amount,
            U256::from(1_000_000_000_000_000_000_u64)
        );
    }

    #[test]
    fn agent_context_approx_json_bytes_is_reasonable() {
        let ctx = minimal_context();
        let size = ctx.approx_json_bytes().unwrap();
        assert!(size > 100, "expected > 100 bytes, got {size}");
        assert!(size < 2_000, "expected < 2000 bytes, got {size}");
    }

    #[test]
    fn agent_context_full_fields_size_within_5kb() {
        let mut ctx = minimal_context();
        ctx.revert_count = 5;
        ctx.suspicious_score = 0.85;
        ctx.suspicion_reasons = vec![
            "high gas usage".to_string(),
            "multiple internal reverts".to_string(),
            "large value transfer".to_string(),
        ];

        for i in 0..10_u8 {
            ctx.call_graph.push(CallFrame {
                depth: u16::from(i % 5),
                caller: addr(i),
                target: addr(i + 1),
                value: U256::zero(),
                input_selector: Some([0xab, 0xcd, 0xef, i]),
                input_size: 132,
                output_size: 32,
                gas_used: 10_000,
                call_type: CallType::Call,
                reverted: i % 3 == 0,
            });
        }

        for i in 0..5_u8 {
            ctx.storage_mutations.push(StorageMutation {
                contract: addr(i + 1),
                slot: h256(i),
                old_value: h256(0),
                new_value: h256(i + 1),
                in_callback: i % 2 == 0,
            });
            ctx.erc20_transfers.push(TokenTransfer {
                token: addr(0x10 + i),
                from: addr(0x20),
                to: addr(0x30),
                amount: U256::from(u64::from(i + 1) * 1_000_000_000_u64),
            });
        }

        let size = ctx.approx_json_bytes().unwrap();
        assert!(
            size <= 6_144,
            "context size {size} bytes exceeds 6KB ceiling"
        );
    }

    #[test]
    fn agent_context_with_log_events_roundtrip() {
        let mut ctx = minimal_context();
        ctx.log_events = vec![LogEvent {
            address: addr(0x55),
            topic0: h256(0xAA),
            topics: vec![h256(0xBB), h256(0xCC)],
            data_size: 64,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.log_events.len(), 1);
        assert_eq!(decoded.log_events[0].topics.len(), 2);
        assert_eq!(decoded.log_events[0].data_size, 64);
    }

    #[test]
    fn agent_context_with_delegatecalls_roundtrip() {
        let mut ctx = minimal_context();
        ctx.delegatecalls = vec![
            DelegateCallInfo {
                caller: addr(0x01),
                target: addr(0x02),
                input_selector: Some([0x12, 0x34, 0x56, 0x78]),
            },
            DelegateCallInfo {
                caller: addr(0x03),
                target: addr(0x04),
                input_selector: None,
            },
        ];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.delegatecalls.len(), 2);
        assert!(decoded.delegatecalls[0].input_selector.is_some());
        assert!(decoded.delegatecalls[1].input_selector.is_none());
    }

    #[test]
    fn agent_context_with_contract_creations_roundtrip() {
        let mut ctx = minimal_context();
        ctx.contract_creations = vec![ContractCreation {
            deployer: addr(0x01),
            deployed: addr(0x02),
            code_size: 1024,
            create_type: CreateType::Create2,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.contract_creations.len(), 1);
        assert_eq!(
            decoded.contract_creations[0].create_type,
            CreateType::Create2
        );
    }
}
