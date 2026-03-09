//! Core data types for the time-travel debugger.

use bytes::Bytes;
use ethrex_common::{Address, H256, U256};
use ethrex_levm::opcodes::Opcode;
use serde::Serialize;

#[cfg(feature = "autopsy")]
use crate::autopsy::types::FundFlow;

/// Data quality indicator for a replay trace.
///
/// When LEVM successfully replays a transaction, all data comes from opcode-level
/// tracing (`High`). When LEVM reverts but the on-chain receipt shows success,
/// fund flows are recovered from receipt logs (`Medium`). `Low` is reserved for
/// partial or missing data.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum DataQuality {
    /// Full opcode-level trace — LEVM execution matched on-chain result.
    #[default]
    High,
    /// Receipt-based fallback — fund flows from logs, not opcode trace.
    Medium,
    /// Partial or missing data.
    Low,
}

/// Configuration for replay trace capture.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayConfig {
    /// Number of stack top items to capture per step (default: 8).
    pub stack_top_capture: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            stack_top_capture: 8,
        }
    }
}

/// A storage write captured during SSTORE execution.
#[derive(Debug, Clone, Serialize)]
pub struct StorageWrite {
    pub address: Address,
    pub slot: H256,
    pub old_value: U256,
    pub new_value: U256,
}

/// A single opcode execution step captured during replay.
#[derive(Debug, Clone, Serialize)]
pub struct StepRecord {
    /// Sequential step index (0-based).
    pub step_index: usize,
    /// Program counter before this opcode executed.
    pub pc: usize,
    /// The opcode byte.
    pub opcode: u8,
    /// Call depth (0 = top-level call).
    pub depth: usize,
    /// Gas remaining before this opcode.
    pub gas_remaining: i64,
    /// Top N stack items (index 0 = top of stack).
    pub stack_top: Vec<U256>,
    /// Total number of items on the stack.
    pub stack_depth: usize,
    /// Current memory size in bytes.
    pub memory_size: usize,
    /// Address of the contract being executed.
    pub code_address: Address,

    /// ETH value sent with CALL/CREATE opcodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_value: Option<U256>,

    /// Storage writes for SSTORE opcodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_writes: Option<Vec<StorageWrite>>,

    /// Log topics for LOG0-LOG4 opcodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_topics: Option<Vec<H256>>,

    /// Log data bytes for LOG0-LOG4 opcodes (capped at 256 bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_data: Option<Vec<u8>>,

    /// First 4 bytes of CALL/DELEGATECALL/STATICCALL/CALLCODE input (function selector).
    /// None if the opcode is not a call, or if input length < 4 bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_input_selector: Option<[u8; 4]>,
}

impl StepRecord {
    /// Return the human-readable opcode name (e.g. "ADD", "PUSH1").
    pub fn opcode_name(&self) -> String {
        format!("{:?}", Opcode::from(self.opcode))
    }
}

/// Complete execution trace from a transaction replay.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayTrace {
    /// All recorded steps.
    pub steps: Vec<StepRecord>,
    /// Configuration used during recording.
    pub config: ReplayConfig,
    /// Total gas used by the transaction.
    pub gas_used: u64,
    /// Whether the transaction succeeded (from LEVM execution).
    pub success: bool,
    /// Transaction output data.
    pub output: Bytes,

    /// Override of `success` from on-chain receipt when LEVM diverges.
    ///
    /// When LEVM reports `success=false` but the receipt shows `status=0x1`,
    /// this field is set to `Some(true)` so downstream code can use the
    /// authoritative on-chain result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success_override: Option<bool>,

    /// Fund flows recovered from receipt logs (when opcode trace is incomplete).
    ///
    /// Populated only when LEVM reverts but the on-chain receipt shows success,
    /// meaning LOG opcodes were never executed in the trace. In that case,
    /// ERC-20 Transfer events are parsed directly from the receipt logs.
    #[cfg(feature = "autopsy")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub receipt_fund_flows: Vec<FundFlow>,

    /// Indicates the quality/source of the trace data.
    pub data_quality: DataQuality,
}

impl ReplayTrace {
    /// Returns the effective success status, preferring the on-chain override.
    ///
    /// Use this instead of `self.success` directly when displaying results
    /// or making decisions based on transaction outcome.
    pub fn effective_success(&self) -> bool {
        self.success_override.unwrap_or(self.success)
    }
}
