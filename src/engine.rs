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
/// - Everything else → [`RevertCause::EvmBehaviorDiff`]
fn revert_cause_from_vm_error(err: &VMError) -> RevertCause {
    match err {
        VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas) => RevertCause::GasExhausted,
        VMError::Internal(InternalError::Database(_) | InternalError::AccountNotFound) => {
            RevertCause::StateDataMiss
        }
        _ => RevertCause::EvmBehaviorDiff,
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

        let revert_cause = if let TxResult::Revert(ref err) = report.result {
            Some(revert_cause_from_vm_error(err))
        } else {
            None
        };

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

#[cfg(test)]
mod tests {
    use ethrex_levm::errors::{DatabaseError, ExceptionalHalt, InternalError, VMError};

    use super::revert_cause_from_vm_error;
    use crate::types::RevertCause;

    #[test]
    fn test_revert_cause_out_of_gas() {
        let err = VMError::ExceptionalHalt(ExceptionalHalt::OutOfGas);
        assert_eq!(revert_cause_from_vm_error(&err), RevertCause::GasExhausted);
    }

    #[test]
    fn test_revert_cause_state_data_miss_account_not_found() {
        let err = VMError::Internal(InternalError::AccountNotFound);
        assert_eq!(
            revert_cause_from_vm_error(&err),
            RevertCause::StateDataMiss
        );
    }

    #[test]
    fn test_revert_cause_state_data_miss_database_error() {
        let err = VMError::Internal(InternalError::Database(DatabaseError::Custom(
            "archive gap".to_string(),
        )));
        assert_eq!(
            revert_cause_from_vm_error(&err),
            RevertCause::StateDataMiss
        );
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
}
