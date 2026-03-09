//! Concrete pipeline step implementations.

use ethrex_common::U256;
use ethrex_common::types::Block;
use ethrex_storage::Store;

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::fund_flow::FundFlowTracer;
use crate::autopsy::types::{DetectedPattern, FundFlow};

use crate::sentinel::ml_model::AnomalyModel;
use crate::sentinel::replay;
use crate::sentinel::types::{AnalysisConfig, SentinelError, SuspiciousTx};

use super::context::{AnalysisContext, AnalysisStep, StepResult};
use super::features::FeatureVector;
use super::{OP_CALL, OP_CALLCODE, OP_DELEGATECALL, OP_STATICCALL};

// ---------------------------------------------------------------------------
// Step 1: Replay the transaction with opcode recording.
// ---------------------------------------------------------------------------

pub struct TraceAnalyzer;

impl AnalysisStep for TraceAnalyzer {
    fn name(&self) -> &'static str {
        "TraceAnalyzer"
    }

    fn execute(
        &self,
        ctx: &mut AnalysisContext,
        store: &Store,
        block: &Block,
        suspicion: &SuspiciousTx,
        config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        let result = replay::replay_tx_from_store(store, block, suspicion.tx_index, config)?;
        ctx.evidence.push(format!(
            "Replayed {} opcode steps",
            result.trace.steps.len()
        ));
        ctx.replay_result = Some(result);
        Ok(StepResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Step 2: Run AttackClassifier to detect known attack patterns.
// ---------------------------------------------------------------------------

pub struct PatternMatcher;

impl AnalysisStep for PatternMatcher {
    fn name(&self) -> &'static str {
        "PatternMatcher"
    }

    fn execute(
        &self,
        ctx: &mut AnalysisContext,
        _store: &Store,
        _block: &Block,
        _suspicion: &SuspiciousTx,
        _config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        let steps = match &ctx.replay_result {
            Some(r) => &r.trace.steps,
            None => return Ok(StepResult::Continue),
        };

        // Dismiss if no CALL opcodes at all (simple transfer, no external interactions)
        let has_calls = steps.iter().any(|s| {
            matches!(
                s.opcode,
                OP_CALL | OP_CALLCODE | OP_DELEGATECALL | OP_STATICCALL
            )
        });

        if !has_calls {
            ctx.evidence
                .push("No CALL opcodes found — dismissed as benign".to_string());
            return Ok(StepResult::Dismiss);
        }

        let patterns = AttackClassifier::classify_with_confidence(steps);
        if !patterns.is_empty() {
            ctx.evidence
                .push(format!("Detected {} attack pattern(s)", patterns.len()));
        }
        ctx.patterns = patterns;
        Ok(StepResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Step 3: Run FundFlowTracer to extract value transfers.
// ---------------------------------------------------------------------------

pub struct FundFlowAnalyzer;

impl AnalysisStep for FundFlowAnalyzer {
    fn name(&self) -> &'static str {
        "FundFlowAnalyzer"
    }

    fn execute(
        &self,
        ctx: &mut AnalysisContext,
        _store: &Store,
        _block: &Block,
        _suspicion: &SuspiciousTx,
        _config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        let steps = match &ctx.replay_result {
            Some(r) => &r.trace.steps,
            None => return Ok(StepResult::Continue),
        };

        let flows = FundFlowTracer::trace(steps);
        if !flows.is_empty() {
            ctx.evidence
                .push(format!("Traced {} fund flow(s)", flows.len()));
        }
        ctx.fund_flows = flows;
        Ok(StepResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Step 4: Extract FeatureVector and run anomaly model.
// ---------------------------------------------------------------------------

pub struct AnomalyDetector;

impl AnalysisStep for AnomalyDetector {
    fn name(&self) -> &'static str {
        "AnomalyDetector"
    }

    fn execute(
        &self,
        _ctx: &mut AnalysisContext,
        _store: &Store,
        _block: &Block,
        _suspicion: &SuspiciousTx,
        _config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        // Actual execution is handled by AnalysisPipeline::execute_step()
        // which calls execute_anomaly_step() with the model.
        Ok(StepResult::Continue)
    }
}

/// Execute the anomaly detection step with access to the model.
pub(super) fn execute_anomaly_step(
    ctx: &mut AnalysisContext,
    model: &dyn AnomalyModel,
) -> Result<StepResult, SentinelError> {
    let (gas_used, gas_limit) = ctx
        .replay_result
        .as_ref()
        .map(|r| (r.trace.gas_used, 30_000_000u64)) // default gas limit
        .unwrap_or((0, 30_000_000));

    let steps = match &ctx.replay_result {
        Some(r) => &r.trace.steps,
        None => return Ok(StepResult::Continue),
    };

    let features = FeatureVector::from_trace(steps, gas_used, gas_limit);
    let score = model.predict(&features);

    ctx.evidence.push(format!("Anomaly score: {score:.4}"));
    ctx.anomaly_score = Some(score);
    ctx.features = Some(features);

    Ok(StepResult::Continue)
}

// ---------------------------------------------------------------------------
// Step 5: Compute final confidence from weighted combination of signals.
// ---------------------------------------------------------------------------

pub struct ConfidenceScorer;

impl AnalysisStep for ConfidenceScorer {
    fn name(&self) -> &'static str {
        "ConfidenceScorer"
    }

    fn execute(
        &self,
        ctx: &mut AnalysisContext,
        _store: &Store,
        _block: &Block,
        suspicion: &SuspiciousTx,
        _config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        let anomaly = ctx.anomaly_score.unwrap_or(0.0);
        let prefilter = suspicion.score;

        // Confidence: pattern 0.4 + anomaly 0.3 + prefilter 0.2 + fund_flow 0.1
        let confidence = {
            let pattern_score = ctx
                .patterns
                .iter()
                .map(|p| p.confidence)
                .fold(0.0_f64, f64::max);

            let fund_flow_score = if ctx.fund_flows.is_empty() {
                0.0
            } else {
                // Normalize: more flows and higher values = higher score
                let total_eth: f64 = ctx
                    .fund_flows
                    .iter()
                    .filter(|f| f.token.is_none())
                    .map(|f| f.value.low_u128() as f64 / 1e18)
                    .sum();
                // Sigmoid-like scaling: 1 - 1/(1+x) where x = total ETH
                1.0 - 1.0 / (1.0 + total_eth)
            };

            pattern_score * 0.4 + anomaly * 0.3 + prefilter * 0.2 + fund_flow_score * 0.1
        };

        ctx.final_confidence = Some(confidence);
        ctx.evidence
            .push(format!("Final confidence: {confidence:.4}"));

        Ok(StepResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Step 6: Generate final alert from accumulated context.
// ---------------------------------------------------------------------------

pub struct ReportGenerator;

impl AnalysisStep for ReportGenerator {
    fn name(&self) -> &'static str {
        "ReportGenerator"
    }

    fn execute(
        &self,
        _ctx: &mut AnalysisContext,
        _store: &Store,
        _block: &Block,
        _suspicion: &SuspiciousTx,
        _config: &AnalysisConfig,
    ) -> Result<StepResult, SentinelError> {
        // Alert generation is handled by AnalysisPipeline::analyze() after all steps.
        // ReportGenerator exists as a pipeline extension point for custom report logic.
        Ok(StepResult::Continue)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(super) fn compute_total_value(flows: &[FundFlow]) -> U256 {
    flows
        .iter()
        .filter(|f| f.token.is_none())
        .fold(U256::zero(), |acc, f| acc.saturating_add(f.value))
}

pub(super) fn generate_summary(
    patterns: &[DetectedPattern],
    total_value: U256,
    block_number: u64,
) -> String {
    use crate::autopsy::types::AttackPattern;

    if patterns.is_empty() {
        return format!("Block {block_number}: anomaly-based alert (no known pattern matched)");
    }

    let pattern_names: Vec<&str> = patterns
        .iter()
        .map(|p| match &p.pattern {
            AttackPattern::Reentrancy { .. } => "Reentrancy",
            AttackPattern::FlashLoan { .. } => "Flash Loan",
            AttackPattern::PriceManipulation { .. } => "Price Manipulation",
            AttackPattern::AccessControlBypass { .. } => "Access Control Bypass",
        })
        .collect();

    let max_conf = patterns
        .iter()
        .map(|p| p.confidence)
        .fold(0.0_f64, f64::max);

    let value_eth = total_value / U256::from(1_000_000_000_000_000_000_u64);

    format!(
        "Block {}: {} detected (confidence {:.0}%, ~{} ETH at risk)",
        block_number,
        pattern_names.join(" + "),
        max_conf * 100.0,
        value_eth,
    )
}
