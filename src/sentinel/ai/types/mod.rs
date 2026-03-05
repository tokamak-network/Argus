//! AI Agent type definitions: AgentContext, AgentVerdict, AttackType, and sub-types.
//!
//! All types are JSON-serializable via serde. Address/H256/U256 use ethrex_common types.

mod attack_type;
mod context;
mod cost_tracker;
mod verdict;

pub use attack_type::{AttackType, CallType, CreateType};
pub use context::{
    AgentContext, CallFrame, ContractCreation, DelegateCallInfo, EthTransfer, LogEvent,
    StorageMutation, TokenTransfer,
};
pub use cost_tracker::CostTracker;
pub use verdict::AgentVerdict;
