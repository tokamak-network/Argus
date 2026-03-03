//! Core data types for the time-travel debugger.

use bytes::Bytes;
use ethrex_common::{Address, H256, U256};
use ethrex_levm::opcodes::Opcode;
use serde::Serialize;

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
}

impl StepRecord {
    /// Return the human-readable opcode name (e.g. "ADD", "PUSH1").
    pub fn opcode_name(&self) -> String {
        format!("{:?}", Opcode::from(self.opcode))
    }
}

/// Complete execution trace from a transaction replay.
#[derive(Debug, Serialize)]
pub struct ReplayTrace {
    /// All recorded steps.
    pub steps: Vec<StepRecord>,
    /// Configuration used during recording.
    pub config: ReplayConfig,
    /// Total gas used by the transaction.
    pub gas_used: u64,
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Transaction output data.
    pub output: Bytes,
}
