//! Transaction replay for sentinel deep analysis.
//!
//! Re-executes a suspicious transaction from local node state with full opcode
//! recording. Unlike the autopsy module (which fetches state from remote archive
//! RPC), this replays against the node's own `Store` via `StoreVmDatabase`.

use std::cell::RefCell;
use std::rc::Rc;

use ethrex_blockchain::vm::StoreVmDatabase;
use ethrex_common::Address;
use ethrex_common::types::{Block, BlockHeader};
use ethrex_levm::tracing::LevmCallTracer;
use ethrex_levm::vm::{VM, VMType};
use ethrex_storage::Store;
use ethrex_vm::Evm;
use ethrex_vm::backends::levm::LEVM;

use crate::recorder::DebugRecorder;
use crate::types::{ReplayConfig, ReplayTrace};

use super::types::{AnalysisConfig, SentinelError};

/// Result of replaying a single transaction with opcode recording.
pub struct ReplayResult {
    /// The full opcode trace.
    pub trace: ReplayTrace,
    /// The recovered sender address.
    pub tx_sender: Address,
    /// The block header containing this transaction.
    pub block_header: BlockHeader,
}

/// Replay a specific transaction from the local Store with opcode recording.
///
/// Steps:
/// 1. Load the parent block header from Store
/// 2. Create `StoreVmDatabase` from parent state root
/// 3. Execute all preceding transactions (0..tx_index) without recording
/// 4. Execute the target transaction WITH `OpcodeRecorder` attached
/// 5. Return the captured trace
pub fn replay_tx_from_store(
    store: &Store,
    block: &Block,
    tx_index: usize,
    analysis_config: &AnalysisConfig,
) -> Result<ReplayResult, SentinelError> {
    let block_number = block.header.number;

    // Validate tx_index
    if tx_index >= block.body.transactions.len() {
        return Err(SentinelError::TxNotFound {
            block_number,
            tx_index,
        });
    }

    // Find parent block header for pre-state
    let parent_hash = block.header.parent_hash;
    let parent_header = store
        .get_block_header_by_hash(parent_hash)
        .map_err(|e| SentinelError::Db(e.to_string()))?
        .ok_or(SentinelError::ParentNotFound { block_number })?;

    // Create StoreVmDatabase from parent state
    let vm_db = StoreVmDatabase::new(store.clone(), parent_header)
        .map_err(|e| SentinelError::Db(e.to_string()))?;

    // Create an Evm instance for environment setup
    let mut evm = Evm::new_for_l1(vm_db);

    // Recover all senders
    let transactions_with_sender =
        block
            .body
            .get_transactions_with_sender()
            .map_err(|e| SentinelError::SenderRecovery {
                tx_index,
                cause: e.to_string(),
            })?;

    // Execute preceding transactions (0..tx_index) without recording
    for (_, (tx, tx_sender)) in transactions_with_sender.iter().enumerate().take(tx_index) {
        LEVM::execute_tx(tx, *tx_sender, &block.header, &mut evm.db, VMType::L1)
            .map_err(|e| SentinelError::Vm(e.to_string()))?;
    }

    // Set up environment for the target TX
    let (target_tx, target_sender) = &transactions_with_sender[tx_index];

    let env = evm
        .setup_env_for_tx(target_tx, &block.header)
        .map_err(|e| SentinelError::Vm(e.to_string()))?;

    // Execute the target TX with opcode recording
    let config = ReplayConfig::default();
    let recorder = Rc::new(RefCell::new(DebugRecorder::new(config.clone())));

    let mut vm = VM::new(
        env,
        &mut evm.db,
        target_tx,
        LevmCallTracer::disabled(),
        VMType::L1,
    )
    .map_err(|e| SentinelError::Vm(e.to_string()))?;

    vm.opcode_recorder = Some(recorder.clone());

    let report = vm.execute().map_err(|e| SentinelError::Vm(e.to_string()))?;

    // Extract steps
    let steps = std::mem::take(&mut recorder.borrow_mut().steps);

    // Check step limit
    if steps.len() > analysis_config.max_steps {
        return Err(SentinelError::StepLimitExceeded {
            steps: steps.len(),
            max_steps: analysis_config.max_steps,
        });
    }

    let trace = ReplayTrace {
        steps,
        config,
        gas_used: report.gas_used,
        success: report.is_success(),
        output: report.output,
    };

    Ok(ReplayResult {
        trace,
        tx_sender: *target_sender,
        block_header: block.header.clone(),
    })
}

/// Load a block header and body from the Store by block number.
///
/// Uses sync methods only: `get_block_header` (sync) for the header.
/// The block body is constructed from the header hash — the caller must
/// ensure the block is committed to the Store before calling this.
pub fn load_block_header(store: &Store, block_number: u64) -> Result<BlockHeader, SentinelError> {
    store
        .get_block_header(block_number)
        .map_err(|e| SentinelError::Db(e.to_string()))?
        .ok_or(SentinelError::BlockNotFound { block_number })
}
