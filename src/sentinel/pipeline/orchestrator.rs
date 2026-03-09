//! Pipeline orchestrator: AnalysisPipeline and PipelineMetrics.

use std::time::Instant;

use ethrex_common::types::Block;
use ethrex_storage::Store;

use super::context::{AnalysisContext, AnalysisStep, StepResult};
use super::steps::{
    AnomalyDetector, ConfidenceScorer, FundFlowAnalyzer, PatternMatcher, ReportGenerator,
    TraceAnalyzer, execute_anomaly_step,
};
use crate::sentinel::ml_model::{AnomalyModel, StatisticalAnomalyDetector};
use crate::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelError, SuspiciousTx};

/// Metrics collected during a single pipeline run.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    pub steps_executed: u32,
    pub steps_dismissed: u32,
    pub total_duration_ms: u64,
    pub step_durations: Vec<(&'static str, u64)>,
}

/// Multi-step adaptive analysis pipeline.
///
/// Steps are executed sequentially. A step can short-circuit (Dismiss),
/// continue, or inject dynamic follow-ups (AddSteps).
pub struct AnalysisPipeline {
    pub(super) steps: Vec<Box<dyn AnalysisStep>>,
    pub(super) anomaly_model: Box<dyn AnomalyModel>,
}

impl AnalysisPipeline {
    /// Build the default pipeline with all available steps.
    ///
    /// 6 steps: trace, pattern, fund-flow, anomaly, confidence, report.
    pub fn default_pipeline() -> Self {
        let steps: Vec<Box<dyn AnalysisStep>> = vec![
            Box::new(TraceAnalyzer),
            Box::new(PatternMatcher),
            Box::new(FundFlowAnalyzer),
            Box::new(AnomalyDetector),
            Box::new(ConfidenceScorer),
            Box::new(ReportGenerator),
        ];

        Self {
            steps,
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        }
    }

    /// Build a pipeline with a custom anomaly model.
    pub fn with_model(mut self, model: Box<dyn AnomalyModel>) -> Self {
        self.anomaly_model = model;
        self
    }

    /// Run the pipeline for a suspicious transaction.
    ///
    /// Returns `Some(SentinelAlert)` if the transaction is confirmed suspicious,
    /// `None` if dismissed as benign.
    pub fn analyze(
        &self,
        store: &Store,
        block: &Block,
        suspicion: &SuspiciousTx,
        config: &AnalysisConfig,
    ) -> Result<(Option<SentinelAlert>, PipelineMetrics), SentinelError> {
        let pipeline_start = Instant::now();
        let mut ctx = AnalysisContext::new();
        let mut metrics = PipelineMetrics::default();
        let mut dynamic_queue: Vec<Box<dyn AnalysisStep>> = Vec::new();
        const MAX_DYNAMIC_STEPS: usize = 64;

        // Run initial steps
        for step in &self.steps {
            if ctx.dismissed {
                break;
            }
            let step_start = Instant::now();
            let result =
                self.execute_step(step.as_ref(), &mut ctx, store, block, suspicion, config)?;
            let elapsed_ms = step_start.elapsed().as_millis() as u64;
            metrics.step_durations.push((step.name(), elapsed_ms));
            metrics.steps_executed += 1;

            match result {
                StepResult::Continue => {}
                StepResult::Dismiss => {
                    ctx.dismissed = true;
                    metrics.steps_dismissed += 1;
                }
                StepResult::AddSteps(new_steps) => {
                    let remaining = MAX_DYNAMIC_STEPS.saturating_sub(dynamic_queue.len());
                    dynamic_queue.extend(new_steps.into_iter().take(remaining));
                }
            }
        }

        // Run dynamic follow-up steps (bounded to prevent DoS)
        let mut dynamic_steps_run = 0usize;
        while let Some(step) = dynamic_queue.pop() {
            if ctx.dismissed || dynamic_steps_run >= MAX_DYNAMIC_STEPS {
                break;
            }
            dynamic_steps_run += 1;
            let step_start = Instant::now();
            let result =
                self.execute_step(step.as_ref(), &mut ctx, store, block, suspicion, config)?;
            let elapsed_ms = step_start.elapsed().as_millis() as u64;
            metrics.step_durations.push((step.name(), elapsed_ms));
            metrics.steps_executed += 1;

            match result {
                StepResult::Continue => {}
                StepResult::Dismiss => {
                    ctx.dismissed = true;
                    metrics.steps_dismissed += 1;
                }
                StepResult::AddSteps(new_steps) => {
                    let remaining = MAX_DYNAMIC_STEPS.saturating_sub(dynamic_queue.len());
                    dynamic_queue.extend(new_steps.into_iter().take(remaining));
                }
            }
        }

        metrics.total_duration_ms = pipeline_start.elapsed().as_millis() as u64;

        if ctx.dismissed {
            return Ok((None, metrics));
        }

        // Check minimum confidence threshold
        let confidence = ctx.final_confidence.unwrap_or(0.0);
        if confidence < config.min_alert_confidence {
            return Ok((None, metrics));
        }

        let alert = ctx.to_alert(block, suspicion);
        Ok((Some(alert), metrics))
    }

    /// Execute a single step, injecting the anomaly model for AnomalyDetector.
    fn execute_step(
        &self,
        step: &dyn AnalysisStep,
        ctx: &mut AnalysisContext,
        store: &Store,
        block: &Block,
        suspicion: &SuspiciousTx,
        config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        // Special handling for AnomalyDetector to inject the model
        if step.name() == "AnomalyDetector" {
            return execute_anomaly_step(ctx, &*self.anomaly_model);
        }
        step.execute(ctx, store, block, suspicion, config)
    }
}
