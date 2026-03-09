//! Replay engine: records a transaction and provides time-travel navigation.

use std::cell::RefCell;
use std::rc::Rc;

use ethrex_common::types::Transaction;
use ethrex_levm::db::gen_db::GeneralizedDatabase;
use ethrex_levm::environment::Environment;
use ethrex_levm::tracing::LevmCallTracer;
use ethrex_levm::vm::{VM, VMType};

use crate::error::DebuggerError;
use crate::recorder::DebugRecorder;
use crate::types::{DataQuality, ReplayConfig, ReplayTrace, StepRecord};

#[cfg(feature = "autopsy")]
use crate::autopsy::fund_flow::FundFlowTracer;
#[cfg(feature = "autopsy")]
use crate::autopsy::rpc_client::EthRpcClient;
#[cfg(feature = "autopsy")]
use ethrex_common::H256;

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
        };

        Ok(Self { trace, cursor: 0 })
    }

    /// Execute and record a transaction, falling back to receipt data on LEVM divergence.
    ///
    /// When LEVM reports `success=false`, this method fetches the on-chain receipt
    /// via `rpc_client`. If the receipt shows `status=0x1` (success), it:
    /// - Sets `success_override = Some(true)`
    /// - Parses Transfer events from receipt logs into `receipt_fund_flows`
    /// - Sets `data_quality = Medium`
    ///
    /// This handles cases where LEVM cannot fully replay complex transactions
    /// (e.g., Aave V3 with deep storage dependencies) but the on-chain result
    /// is authoritative.
    #[cfg(feature = "autopsy")]
    pub fn record_with_receipt_fallback(
        db: &mut GeneralizedDatabase,
        env: Environment,
        tx: &Transaction,
        config: ReplayConfig,
        rpc_client: &EthRpcClient,
        tx_hash: H256,
    ) -> Result<Self, DebuggerError> {
        let mut engine = Self::record(db, env, tx, config)?;

        if !engine.trace.success {
            // LEVM reverted — check on-chain receipt for the authoritative result
            match rpc_client.eth_get_transaction_receipt(tx_hash) {
                Ok(receipt) => {
                    if receipt.status {
                        engine.trace.success_override = Some(true);
                        engine.trace.receipt_fund_flows =
                            FundFlowTracer::trace_from_receipt_logs(&receipt.logs);
                        engine.trace.data_quality = DataQuality::Medium;
                    }
                }
                Err(e) => {
                    // Receipt fetch failed — log but don't fail the entire replay.
                    // The trace is still valid, just without the fallback data.
                    eprintln!("Warning: receipt fallback failed for tx 0x{tx_hash:x}: {e}");
                }
            }
        }

        Ok(engine)
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
