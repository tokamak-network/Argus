//! Replay engine: records a transaction and provides time-travel navigation.

use std::cell::RefCell;
use std::rc::Rc;

use ethrex_common::types::Transaction;
use ethrex_levm::db::gen_db::GeneralizedDatabase;
use ethrex_levm::environment::Environment;
use ethrex_levm::tracing::LevmCallTracer;
use ethrex_levm::vm::{VM, VMType};

use ethrex_levm::errors::{ExceptionalHalt, InternalError, TxResult, VMError};

use crate::error::DebuggerError;
use crate::recorder::DebugRecorder;
use crate::types::{DataQuality, ReplayConfig, ReplayTrace, RevertCause, StepRecord};

/// Map a LEVM [`VMError`] to the higher-level [`RevertCause`] classification.
///
/// - [`ExceptionalHalt::OutOfGas`] → [`RevertCause::GasExhausted`]
/// - [`InternalError::Database`] / [`InternalError::AccountNotFound`] →
///   [`RevertCause::StateDataMiss`] (archive node gap)
/// - [`VMError::TxValidation`] → [`RevertCause::EvmBehaviorDiff`]
///   (tx rejected before execution; not a state-data gap or gas issue)
/// - Everything else → [`RevertCause::EvmBehaviorDiff`]
pub(crate) fn revert_cause_from_vm_error(err: &VMError) -> RevertCause {
    match err {
        VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas) => RevertCause::GasExhausted,
        VMError::Internal(InternalError::Database(_) | InternalError::AccountNotFound) => {
            RevertCause::StateDataMiss
        }
        // Exhaustive arms instead of `_` wildcard: if ethrex adds a new VMError
        // variant the compiler forces us to classify it rather than silently
        // falling through to EvmBehaviorDiff.
        VMError::TxValidation(_)
        | VMError::ExceptionalHalt(_)
        | VMError::RevertOpcode
        | VMError::Internal(_) => RevertCause::EvmBehaviorDiff,
    }
}

/// Extract [`RevertCause`] from a [`TxResult`].
///
/// Returns `Some(cause)` when the result is [`TxResult::Revert`], `None`
/// when the transaction succeeded. Use this instead of the three-line
/// `if let TxResult::Revert` pattern at every call site.
pub(crate) fn revert_cause_from_report(result: &TxResult) -> Option<RevertCause> {
    if let TxResult::Revert(err) = result {
        Some(revert_cause_from_vm_error(err))
    } else {
        None
    }
}

/// Time-travel replay engine.
///
/// Records a full transaction execution at opcode granularity, then allows
/// forward/backward/random-access navigation through the trace.
pub struct ReplayEngine {
    trace: ReplayTrace,
    cursor: usize,
}

impl ReplayEngine {
    /// Execute a transaction and record every opcode step.
    ///
    /// The `db` is mutated during execution (standard LEVM behavior).
    /// After this call, the engine holds the complete trace and is positioned
    /// at step 0.
    pub fn record(
        db: &mut GeneralizedDatabase,
        env: Environment,
        tx: &Transaction,
        config: ReplayConfig,
    ) -> Result<Self, DebuggerError> {
        let recorder = Rc::new(RefCell::new(DebugRecorder::new(config.clone())));

        let mut vm = VM::new(env, db, tx, LevmCallTracer::disabled(), VMType::L1)?;

        vm.opcode_recorder = Some(recorder.clone());

        let report = vm.execute()?;

        // Extract steps by taking from the recorder (avoids Rc::try_unwrap
        // issues since VM still holds a clone of the Rc).
        let steps = std::mem::take(&mut recorder.borrow_mut().steps);

        let revert_cause = revert_cause_from_report(&report.result);

        let trace = ReplayTrace {
            steps,
            config,
            gas_used: report.gas_used,
            success: report.is_success(),
            output: report.output,
            success_override: None,
            #[cfg(feature = "autopsy")]
            receipt_fund_flows: Vec::new(),
            data_quality: DataQuality::High,
            revert_cause,
        };

        Ok(Self { trace, cursor: 0 })
    }

    /// Total number of recorded steps.
    pub fn len(&self) -> usize {
        self.trace.steps.len()
    }

    /// Whether the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.trace.steps.is_empty()
    }

    /// Current cursor position (0-based step index).
    pub fn position(&self) -> usize {
        self.cursor
    }

    /// Get the step at the current cursor position.
    pub fn current_step(&self) -> Option<&StepRecord> {
        self.trace.steps.get(self.cursor)
    }

    /// Move cursor forward by one step, returning the new current step.
    ///
    /// Returns `None` if already at the last step.
    pub fn forward(&mut self) -> Option<&StepRecord> {
        let next = self.cursor.checked_add(1)?;
        if next >= self.trace.steps.len() {
            return None;
        }
        self.cursor = next;
        self.trace.steps.get(self.cursor)
    }

    /// Move cursor backward by one step, returning the new current step.
    ///
    /// Returns `None` if already at step 0.
    pub fn backward(&mut self) -> Option<&StepRecord> {
        let prev = self.cursor.checked_sub(1)?;
        self.cursor = prev;
        self.trace.steps.get(self.cursor)
    }

    /// Jump to an arbitrary step index, returning the step there.
    ///
    /// Returns `None` if `step` is out of range.
    pub fn goto(&mut self, step: usize) -> Option<&StepRecord> {
        if step >= self.trace.steps.len() {
            return None;
        }
        self.cursor = step;
        self.trace.steps.get(self.cursor)
    }

    /// Get a slice of steps starting from `start` with at most `count` items.
    pub fn steps_range(&self, start: usize, count: usize) -> &[StepRecord] {
        let len = self.trace.steps.len();
        if start >= len {
            return &[];
        }
        let end = len.min(start.saturating_add(count));
        &self.trace.steps[start..end]
    }

    /// Access the full replay trace.
    pub fn trace(&self) -> &ReplayTrace {
        &self.trace
    }

    /// Consume the engine and return the owned trace.
    pub fn into_trace(self) -> ReplayTrace {
        self.trace
    }
}

// ---------------------------------------------------------------------------
// Autopsy: prior same-sender TX replay helpers
// ---------------------------------------------------------------------------

/// Find prior transactions from the same sender as the target transaction.
///
/// Returns all transactions from `block_txs` that:
/// - have the same `from` address as `target_tx`
/// - appear before `target_tx` in the block (by vector index)
///
/// The target TX is identified by its hash. When the target TX is not found
/// in `block_txs` (or appears at index 0), an empty Vec is returned.
#[cfg(any(all(feature = "autopsy", feature = "cli"), test))]
pub(crate) fn find_prior_same_sender_txs(
    block_txs: &[crate::autopsy::rpc_client::RpcTransaction],
    target_tx: &crate::autopsy::rpc_client::RpcTransaction,
) -> Vec<crate::autopsy::rpc_client::RpcTransaction> {
    let target_index = block_txs
        .iter()
        .position(|tx| tx.hash == target_tx.hash)
        .unwrap_or(0);

    block_txs[..target_index]
        .iter()
        .filter(|tx| tx.from == target_tx.from)
        .cloned()
        .collect()
}

/// Replay prior same-sender transactions to establish correct nonce state.
///
/// Executes each transaction in `prior_txs` against `db` in order, updating
/// the EVM state (account nonce, storage, balances). Results are discarded —
/// only the state update matters. When a prior TX fails, logs a warning and
/// continues (best-effort).
///
/// If `prior_txs.len() > max_prior_txs`, only the first `max_prior_txs`
/// are replayed and a `[WARNING]` is emitted.
#[cfg(any(all(feature = "autopsy", feature = "cli"), test))]
pub(crate) fn replay_prior_txs(
    db: &mut GeneralizedDatabase,
    block_header: &crate::autopsy::rpc_client::RpcBlockHeader,
    prior_txs: &[crate::autopsy::rpc_client::RpcTransaction],
    max_prior_txs: usize,
) -> Vec<crate::types::PriorTxReplayResult> {
    use crate::autopsy::rpc_client::{build_env_from_rpc, rpc_tx_to_ethrex};

    let total = prior_txs.len();
    if total > max_prior_txs {
        eprintln!(
            "[autopsy] [WARNING] {total} prior txs from same sender exceed \
             max_prior_txs={max_prior_txs}. Replaying first {max_prior_txs} only."
        );
    }

    let limit = total.min(max_prior_txs);
    let mut results = Vec::with_capacity(limit);

    for (i, rpc_tx) in prior_txs[..limit].iter().enumerate() {
        let env = build_env_from_rpc(rpc_tx, block_header);
        let tx = rpc_tx_to_ethrex(rpc_tx);
        let hash_short: String = format!("0x{:x}", rpc_tx.hash).chars().take(10).collect();
        eprintln!(
            "[autopsy] Replaying prior tx {}/{}: {}... (nonce {})",
            i + 1,
            limit,
            hash_short,
            rpc_tx.nonce,
        );

        let (success, error) = match VM::new(env, db, &tx, LevmCallTracer::disabled(), VMType::L1) {
            Err(e) => (false, Some(format!("VM init: {e}"))),
            Ok(mut vm) => match vm.execute() {
                Ok(_) => (true, None),
                Err(e) => (false, Some(format!("VM exec: {e}"))),
            },
        };

        if success {
            eprintln!("[autopsy] Prior tx {}/{} replayed ✓", i + 1, limit);
        } else if let Some(ref err_msg) = error {
            eprintln!(
                "[autopsy] [WARNING] Prior tx {}/{} failed: {}. Continuing.",
                i + 1,
                limit,
                err_msg
            );
        }

        results.push(crate::types::PriorTxReplayResult {
            tx_hash: rpc_tx.hash,
            nonce: rpc_tx.nonce,
            success,
            error,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use ethrex_levm::errors::{DatabaseError, ExceptionalHalt, InternalError, TxResult, VMError};

    use super::{revert_cause_from_report, revert_cause_from_vm_error};
    use crate::types::RevertCause;

    #[test]
    fn test_revert_cause_out_of_gas() {
        let err = VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas);
        assert_eq!(revert_cause_from_vm_error(&err), RevertCause::GasExhausted);
    }

    #[test]
    fn test_revert_cause_state_data_miss_account_not_found() {
        let err = VMError::Internal(InternalError::AccountNotFound);
        assert_eq!(revert_cause_from_vm_error(&err), RevertCause::StateDataMiss);
    }

    #[test]
    fn test_revert_cause_state_data_miss_database_error() {
        let err = VMError::Internal(InternalError::Database(DatabaseError::Custom(
            "archive gap".to_string(),
        )));
        assert_eq!(revert_cause_from_vm_error(&err), RevertCause::StateDataMiss);
    }

    #[test]
    fn test_revert_cause_evm_behavior_diff_revert_opcode() {
        let err = VMError::RevertOpcode;
        assert_eq!(
            revert_cause_from_vm_error(&err),
            RevertCause::EvmBehaviorDiff
        );
    }

    #[test]
    fn test_revert_cause_evm_behavior_diff_stack_underflow() {
        let err = VMError::ExceptionalHalt(ExceptionalHalt::StackUnderflow);
        assert_eq!(
            revert_cause_from_vm_error(&err),
            RevertCause::EvmBehaviorDiff
        );
    }

    #[test]
    fn test_revert_cause_from_report_revert() {
        let result = TxResult::Revert(VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas));
        assert_eq!(
            revert_cause_from_report(&result),
            Some(RevertCause::GasExhausted)
        );
    }

    #[test]
    fn test_revert_cause_from_report_success() {
        let result = TxResult::Success;
        assert_eq!(revert_cause_from_report(&result), None);
    }
}
