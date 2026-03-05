//! Core pipeline types: StepResult, AnalysisStep trait, and AnalysisContext.

use ethrex_common::types::Block;
use ethrex_storage::Store;

#[cfg(feature = "autopsy")]
use crate::autopsy::types::{DetectedPattern, FundFlow};

use super::features::FeatureVector;
#[cfg(feature = "autopsy")]
use super::steps::{compute_total_value, generate_summary};
use crate::sentinel::replay::ReplayResult;
use crate::sentinel::types::{
    AlertPriority, AnalysisConfig, SentinelAlert, SentinelError, SuspiciousTx,
};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Result of a single pipeline step execution.
pub enum StepResult {
    /// Continue to the next step.
    Continue,
    /// Dismiss the transaction as benign (early exit).
    Dismiss,
    /// Add dynamic follow-up steps to the pipeline queue.
    AddSteps(Vec<Box<dyn AnalysisStep>>),
}

/// A single analysis step in the pipeline.
pub trait AnalysisStep: Send {
    /// Human-readable name for observability.
    fn name(&self) -> &'static str;

    /// Execute this step, mutating the shared analysis context.
    fn execute(
        &self,
        ctx: &mut AnalysisContext,
        store: &Store,
        block: &Block,
        suspicion: &SuspiciousTx,
        config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError>;
}

/// Shared mutable context passed through all pipeline steps.
pub struct AnalysisContext {
    /// Replay result from TraceAnalyzer (populated by step 1).
    pub replay_result: Option<ReplayResult>,
    /// Attack patterns detected by the classifier.
    #[cfg(feature = "autopsy")]
    pub patterns: Vec<DetectedPattern>,
    /// Fund flows extracted by the tracer.
    #[cfg(feature = "autopsy")]
    pub fund_flows: Vec<FundFlow>,
    /// Extracted numerical features for anomaly scoring.
    pub features: Option<FeatureVector>,
    /// Anomaly score from the ML model (0.0 benign .. 1.0 malicious).
    pub anomaly_score: Option<f64>,
    /// Final combined confidence score.
    pub final_confidence: Option<f64>,
    /// Human-readable evidence strings accumulated across steps.
    pub evidence: Vec<String>,
    /// When true, the pipeline short-circuits and returns None.
    pub dismissed: bool,
}

impl AnalysisContext {
    pub(super) fn new() -> Self {
        Self {
            replay_result: None,
            #[cfg(feature = "autopsy")]
            patterns: Vec::new(),
            #[cfg(feature = "autopsy")]
            fund_flows: Vec::new(),
            features: None,
            anomaly_score: None,
            final_confidence: None,
            evidence: Vec::new(),
            dismissed: false,
        }
    }

    /// Build a `SentinelAlert` from the accumulated context.
    pub(super) fn to_alert(&self, block: &Block, suspicion: &SuspiciousTx) -> SentinelAlert {
        let block_number = block.header.number;
        let block_hash = block.header.hash();

        let total_steps = self
            .replay_result
            .as_ref()
            .map(|r| r.trace.steps.len())
            .unwrap_or(0);

        let confidence = self.final_confidence.unwrap_or(suspicion.score);
        let combined = suspicion.score.max(confidence);
        let alert_priority = AlertPriority::from_score(combined);

        #[cfg(feature = "autopsy")]
        let total_value_at_risk = compute_total_value(&self.fund_flows);
        #[cfg(not(feature = "autopsy"))]
        let total_value_at_risk = ethrex_common::U256::zero();

        #[cfg(feature = "autopsy")]
        let summary = generate_summary(&self.patterns, total_value_at_risk, block_number);
        #[cfg(not(feature = "autopsy"))]
        let summary = format!(
            "Block {}: anomaly score {:.2}, confidence {:.2}",
            block_number,
            self.anomaly_score.unwrap_or(0.0),
            confidence,
        );

        SentinelAlert {
            block_number,
            block_hash,
            tx_hash: suspicion.tx_hash,
            tx_index: suspicion.tx_index,
            alert_priority,
            suspicion_reasons: suspicion.reasons.clone(),
            suspicion_score: combined,
            #[cfg(feature = "autopsy")]
            detected_patterns: self.patterns.clone(),
            #[cfg(feature = "autopsy")]
            fund_flows: self.fund_flows.clone(),
            total_value_at_risk,
            whitelist_matches: suspicion.whitelist_matches,
            summary,
            total_steps,
            feature_vector: self.features.clone(),
        }
    }
}
