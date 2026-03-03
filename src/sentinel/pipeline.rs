//! Adaptive multi-step analysis pipeline for the sentinel.
//!
//! Replaces the fixed `DeepAnalyzer` flow with a dynamic pipeline that can
//! skip, add, or reorder steps at runtime. Each step implements the
//! `AnalysisStep` trait and can early-exit (dismiss) or inject follow-up steps.

use std::collections::HashSet;
use std::time::Instant;

use ethrex_common::types::Block;
use ethrex_common::U256;
use ethrex_storage::Store;

#[cfg(feature = "autopsy")]
use crate::autopsy::classifier::AttackClassifier;
#[cfg(feature = "autopsy")]
use crate::autopsy::fund_flow::FundFlowTracer;
#[cfg(feature = "autopsy")]
use crate::autopsy::types::{DetectedPattern, FundFlow};

use crate::types::StepRecord;

use super::ml_model::{AnomalyModel, StatisticalAnomalyDetector};
use super::replay::{self, ReplayResult};
use super::types::{
    AlertPriority, AnalysisConfig, SentinelAlert, SentinelError, SuspiciousTx,
};

// Opcode constants for feature extraction
const OP_SLOAD: u8 = 0x54;
const OP_SSTORE: u8 = 0x55;
const OP_CALL: u8 = 0xF1;
const OP_CALLCODE: u8 = 0xF2;
const OP_DELEGATECALL: u8 = 0xF4;
const OP_CREATE: u8 = 0xF0;
const OP_CREATE2: u8 = 0xF5;
const OP_STATICCALL: u8 = 0xFA;
const OP_SELFDESTRUCT: u8 = 0xFF;
const OP_REVERT: u8 = 0xFD;
const OP_LOG0: u8 = 0xA0;
const OP_LOG4: u8 = 0xA4;

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
    fn new() -> Self {
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
    fn to_alert(&self, block: &Block, suspicion: &SuspiciousTx) -> SentinelAlert {
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
        let total_value_at_risk = U256::zero();

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
            // Use combined score (max of prefilter heuristic and pipeline confidence)
            // so downstream handlers (AutoPauseHandler) use the best available signal.
            suspicion_score: combined,
            #[cfg(feature = "autopsy")]
            detected_patterns: self.patterns.clone(),
            #[cfg(feature = "autopsy")]
            fund_flows: self.fund_flows.clone(),
            total_value_at_risk,
            summary,
            total_steps,
            feature_vector: self.features.clone(),
        }
    }
}

/// Numerical feature vector extracted from an execution trace.
///
/// All fields use `f64` for compatibility with the anomaly model's z-score math.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FeatureVector {
    pub total_steps: f64,
    pub unique_addresses: f64,
    pub max_call_depth: f64,
    pub sstore_count: f64,
    pub sload_count: f64,
    pub call_count: f64,
    pub delegatecall_count: f64,
    pub staticcall_count: f64,
    pub create_count: f64,
    pub selfdestruct_count: f64,
    pub log_count: f64,
    pub revert_count: f64,
    pub reentrancy_depth: f64,
    pub eth_transferred_wei: f64,
    pub gas_ratio: f64,
    pub calldata_entropy: f64,
}

impl FeatureVector {
    /// Extract a feature vector from an execution trace.
    pub fn from_trace(steps: &[StepRecord], gas_used: u64, gas_limit: u64) -> Self {
        let mut addresses = HashSet::new();
        let mut max_depth: usize = 0;
        let mut sstore = 0u32;
        let mut sload = 0u32;
        let mut call = 0u32;
        let mut delegatecall = 0u32;
        let mut staticcall = 0u32;
        let mut create = 0u32;
        let mut selfdestruct = 0u32;
        let mut log = 0u32;
        let mut revert = 0u32;
        let mut eth_total: f64 = 0.0;

        for step in steps {
            addresses.insert(step.code_address);
            if step.depth > max_depth {
                max_depth = step.depth;
            }
            match step.opcode {
                OP_SLOAD => sload += 1,
                OP_SSTORE => sstore += 1,
                OP_CALL | OP_CALLCODE => {
                    call += 1;
                    if let Some(val) = &step.call_value
                        && *val > U256::zero()
                    {
                        eth_total += val.low_u128() as f64;
                    }
                }
                OP_DELEGATECALL => delegatecall += 1,
                OP_STATICCALL => staticcall += 1,
                OP_CREATE | OP_CREATE2 => create += 1,
                OP_SELFDESTRUCT => selfdestruct += 1,
                OP_REVERT => revert += 1,
                op if (OP_LOG0..=OP_LOG4).contains(&op) => log += 1,
                _ => {}
            }
        }

        let gas_ratio = if gas_limit > 0 {
            gas_used as f64 / gas_limit as f64
        } else {
            0.0
        };

        // Reentrancy depth: max number of times we see the same address at
        // increasing call depths within the trace.
        let reentrancy_depth = detect_reentrancy_depth(steps);

        Self {
            total_steps: steps.len() as f64,
            unique_addresses: addresses.len() as f64,
            max_call_depth: max_depth as f64,
            sstore_count: sstore as f64,
            sload_count: sload as f64,
            call_count: call as f64,
            delegatecall_count: delegatecall as f64,
            staticcall_count: staticcall as f64,
            create_count: create as f64,
            selfdestruct_count: selfdestruct as f64,
            log_count: log as f64,
            revert_count: revert as f64,
            reentrancy_depth: reentrancy_depth as f64,
            eth_transferred_wei: eth_total,
            gas_ratio,
            calldata_entropy: 0.0, // placeholder — calldata not in trace
        }
    }
}

/// Detect reentrancy depth by counting re-entries to the same address at
/// increasing call depths.
fn detect_reentrancy_depth(steps: &[StepRecord]) -> u32 {
    use std::collections::HashMap;

    // Track the first depth at which each address appears, then count
    // how many times an address appears at a deeper level than its first.
    let mut first_depth: HashMap<ethrex_common::Address, usize> = HashMap::new();
    let mut max_reentry = 0u32;

    for step in steps {
        if matches!(step.opcode, OP_CALL | OP_CALLCODE | OP_DELEGATECALL | OP_STATICCALL) {
            let addr = step.code_address;
            match first_depth.get(&addr) {
                Some(&first) if step.depth > first => {
                    let depth = (step.depth - first) as u32;
                    if depth > max_reentry {
                        max_reentry = depth;
                    }
                }
                None => {
                    first_depth.insert(addr, step.depth);
                }
                _ => {}
            }
        }
    }

    max_reentry
}

// ---------------------------------------------------------------------------
// Pipeline orchestrator
// ---------------------------------------------------------------------------

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
    steps: Vec<Box<dyn AnalysisStep>>,
    anomaly_model: Box<dyn AnomalyModel>,
}

impl AnalysisPipeline {
    /// Build the default pipeline with all available steps.
    ///
    /// With the `autopsy` feature: 6 steps (trace, pattern, fund-flow, anomaly, confidence, report).
    /// Without `autopsy`: 4 steps (trace, anomaly, confidence, report).
    #[allow(clippy::vec_init_then_push)] // cfg-gated pushes prevent vec![] macro usage
    pub fn default_pipeline() -> Self {
        let mut steps: Vec<Box<dyn AnalysisStep>> = Vec::new();

        steps.push(Box::new(TraceAnalyzer));

        #[cfg(feature = "autopsy")]
        {
            steps.push(Box::new(PatternMatcher));
            steps.push(Box::new(FundFlowAnalyzer));
        }

        steps.push(Box::new(AnomalyDetector));
        steps.push(Box::new(ConfidenceScorer));
        steps.push(Box::new(ReportGenerator));

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
            let result = self.execute_step(step.as_ref(), &mut ctx, store, block, suspicion, config)?;
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
            let result = self.execute_step(step.as_ref(), &mut ctx, store, block, suspicion, config)?;
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

// ---------------------------------------------------------------------------
// Concrete pipeline steps
// ---------------------------------------------------------------------------

/// Step 1: Replay the transaction with opcode recording.
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

/// Step 2: Run AttackClassifier to detect known attack patterns.
/// cfg-gated to `autopsy` feature.
#[cfg(feature = "autopsy")]
pub struct PatternMatcher;

#[cfg(feature = "autopsy")]
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
        let has_calls = steps
            .iter()
            .any(|s| matches!(s.opcode, OP_CALL | OP_CALLCODE | OP_DELEGATECALL | OP_STATICCALL));

        if !has_calls {
            ctx.evidence
                .push("No CALL opcodes found — dismissed as benign".to_string());
            return Ok(StepResult::Dismiss);
        }

        let patterns = AttackClassifier::classify_with_confidence(steps);
        if !patterns.is_empty() {
            ctx.evidence.push(format!(
                "Detected {} attack pattern(s)",
                patterns.len()
            ));
        }
        ctx.patterns = patterns;
        Ok(StepResult::Continue)
    }
}

/// Step 3: Run FundFlowTracer to extract value transfers.
/// cfg-gated to `autopsy` feature.
#[cfg(feature = "autopsy")]
pub struct FundFlowAnalyzer;

#[cfg(feature = "autopsy")]
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

/// Step 4: Extract FeatureVector and run anomaly model.
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
fn execute_anomaly_step(
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

    ctx.evidence
        .push(format!("Anomaly score: {score:.4}"));
    ctx.anomaly_score = Some(score);
    ctx.features = Some(features);

    Ok(StepResult::Continue)
}

/// Step 5: Compute final confidence from weighted combination of signals.
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

        // With autopsy: pattern 0.4 + anomaly 0.3 + prefilter 0.2 + fund_flow 0.1
        // Without autopsy: anomaly 0.6 + prefilter 0.4
        #[cfg(feature = "autopsy")]
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

        #[cfg(not(feature = "autopsy"))]
        let confidence = anomaly * 0.6 + prefilter * 0.4;

        ctx.final_confidence = Some(confidence);
        ctx.evidence
            .push(format!("Final confidence: {confidence:.4}"));

        Ok(StepResult::Continue)
    }
}

/// Step 6: Generate final alert from accumulated context.
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

#[cfg(feature = "autopsy")]
fn compute_total_value(flows: &[FundFlow]) -> U256 {
    flows
        .iter()
        .filter(|f| f.token.is_none())
        .fold(U256::zero(), |acc, f| acc.saturating_add(f.value))
}

#[cfg(feature = "autopsy")]
fn generate_summary(
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{Address, H256};
    use ethrex_storage::EngineType;

    fn make_step(opcode: u8, depth: usize, addr: Address) -> StepRecord {
        StepRecord {
            step_index: 0,
            pc: 0,
            opcode,
            depth,
            gas_remaining: 1_000_000,
            stack_top: vec![],
            stack_depth: 0,
            memory_size: 0,
            code_address: addr,
            call_value: None,
            storage_writes: None,
            log_topics: None,
            log_data: None,
        }
    }

    fn make_step_with_index(opcode: u8, depth: usize, addr: Address, idx: usize) -> StepRecord {
        let mut step = make_step(opcode, depth, addr);
        step.step_index = idx;
        step
    }

    // -- FeatureVector extraction tests --

    #[test]
    fn feature_vector_simple_trace() {
        let addr = Address::from_slice(&[0x01; 20]);
        let steps = vec![
            make_step(OP_SLOAD, 0, addr),
            make_step(OP_SSTORE, 0, addr),
            make_step(OP_CALL, 0, addr),
        ];

        let fv = FeatureVector::from_trace(&steps, 50_000, 100_000);

        assert!((fv.total_steps - 3.0).abs() < f64::EPSILON);
        assert!((fv.unique_addresses - 1.0).abs() < f64::EPSILON);
        assert!((fv.sload_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.sstore_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.call_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.gas_ratio - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn feature_vector_complex_trace() {
        let addr1 = Address::from_slice(&[0x01; 20]);
        let addr2 = Address::from_slice(&[0x02; 20]);
        let steps = vec![
            make_step(OP_CALL, 0, addr1),
            make_step(OP_DELEGATECALL, 1, addr1),
            make_step(OP_STATICCALL, 2, addr2),
            make_step(OP_SSTORE, 2, addr2),
            make_step(OP_SLOAD, 1, addr1),
            make_step(OP_CREATE, 0, addr1),
            make_step(0xA2, 0, addr1), // LOG2
            make_step(OP_REVERT, 0, addr1),
        ];

        let fv = FeatureVector::from_trace(&steps, 90_000, 100_000);

        assert!((fv.total_steps - 8.0).abs() < f64::EPSILON);
        assert!((fv.unique_addresses - 2.0).abs() < f64::EPSILON);
        assert!((fv.max_call_depth - 2.0).abs() < f64::EPSILON);
        assert!((fv.call_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.delegatecall_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.staticcall_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.create_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.log_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.revert_count - 1.0).abs() < f64::EPSILON);
        assert!((fv.gas_ratio - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn feature_vector_empty_trace() {
        let fv = FeatureVector::from_trace(&[], 0, 100_000);

        assert!((fv.total_steps).abs() < f64::EPSILON);
        assert!((fv.unique_addresses).abs() < f64::EPSILON);
        assert!((fv.gas_ratio).abs() < f64::EPSILON);
    }

    // -- Dismiss/skip tests --

    #[test]
    fn pipeline_dismissed_flag_respected() {
        // A step that dismisses should prevent subsequent steps from executing.
        struct DismissStep;
        impl AnalysisStep for DismissStep {
            fn name(&self) -> &'static str {
                "DismissStep"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                Ok(StepResult::Dismiss)
            }
        }

        struct PanicStep;
        impl AnalysisStep for PanicStep {
            fn name(&self) -> &'static str {
                "PanicStep"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                panic!("PanicStep should never be reached");
            }
        }

        let pipeline = AnalysisPipeline {
            steps: vec![Box::new(DismissStep), Box::new(PanicStep)],
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        };

        let store = Store::new("test-dismiss", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };
        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.5,
            priority: AlertPriority::Medium,
        };
        let config = AnalysisConfig::default();

        let (result, metrics) = pipeline
            .analyze(&store, &block, &suspicion, &config)
            .unwrap();
        assert!(result.is_none(), "dismissed TX should produce no alert");
        assert_eq!(metrics.steps_dismissed, 1);
        assert_eq!(metrics.steps_executed, 1); // only DismissStep ran
    }

    // -- Dynamic AddSteps tests --

    #[test]
    fn pipeline_add_steps_queues_dynamic_follow_up() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let follow_up_ran = Arc::new(AtomicBool::new(false));
        let follow_up_clone = follow_up_ran.clone();

        struct FollowUpStep {
            ran: Arc<AtomicBool>,
        }
        impl AnalysisStep for FollowUpStep {
            fn name(&self) -> &'static str {
                "FollowUp"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                self.ran.store(true, Ordering::SeqCst);
                Ok(StepResult::Continue)
            }
        }

        struct AdderStep {
            follow_up_ran: Arc<AtomicBool>,
        }
        impl AnalysisStep for AdderStep {
            fn name(&self) -> &'static str {
                "Adder"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                Ok(StepResult::AddSteps(vec![Box::new(FollowUpStep {
                    ran: self.follow_up_ran.clone(),
                })]))
            }
        }

        let pipeline = AnalysisPipeline {
            steps: vec![Box::new(AdderStep {
                follow_up_ran: follow_up_clone,
            })],
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        };

        let store = Store::new("test-add-steps", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };
        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.5,
            priority: AlertPriority::Medium,
        };
        let config = AnalysisConfig {
            min_alert_confidence: 0.0,
            ..Default::default()
        };

        let (_result, metrics) = pipeline
            .analyze(&store, &block, &suspicion, &config)
            .unwrap();
        assert!(
            follow_up_ran.load(Ordering::SeqCst),
            "follow-up step should have run"
        );
        assert_eq!(metrics.steps_executed, 2); // Adder + FollowUp
    }

    #[test]
    fn pipeline_empty_add_steps() {
        struct EmptyAdder;
        impl AnalysisStep for EmptyAdder {
            fn name(&self) -> &'static str {
                "EmptyAdder"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                Ok(StepResult::AddSteps(vec![]))
            }
        }

        let pipeline = AnalysisPipeline {
            steps: vec![Box::new(EmptyAdder)],
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        };

        let store = Store::new("test-empty-add", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };
        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.5,
            priority: AlertPriority::Medium,
        };
        let config = AnalysisConfig {
            min_alert_confidence: 0.0,
            ..Default::default()
        };

        let (_result, metrics) = pipeline
            .analyze(&store, &block, &suspicion, &config)
            .unwrap();
        assert_eq!(metrics.steps_executed, 1);
    }

    // -- Confidence scoring tests --

    #[test]
    fn confidence_prefilter_only_without_autopsy() {
        // When no replay result is available, confidence should still be computed
        // from prefilter score.
        let mut ctx = AnalysisContext::new();
        ctx.anomaly_score = Some(0.6);

        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.8,
            priority: AlertPriority::High,
        };
        let config = AnalysisConfig::default();
        let store = Store::new("test-conf", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };

        let scorer = ConfidenceScorer;
        scorer
            .execute(&mut ctx, &store, &block, &suspicion, &config)
            .unwrap();

        let confidence = ctx.final_confidence.unwrap();
        // Without autopsy: anomaly * 0.6 + prefilter * 0.4 = 0.6*0.6 + 0.8*0.4 = 0.68
        // With autopsy: pattern * 0.4 + anomaly * 0.3 + prefilter * 0.2 + fund_flow * 0.1
        assert!(confidence > 0.0, "confidence should be positive");
        assert!(confidence <= 1.0, "confidence should be <= 1.0");
    }

    // -- Reentrancy depth detection --

    #[test]
    fn reentrancy_depth_detection() {
        let addr = Address::from_slice(&[0xAA; 20]);
        let steps = vec![
            make_step_with_index(OP_CALL, 0, addr, 0),
            make_step_with_index(OP_SLOAD, 1, addr, 1),
            make_step_with_index(OP_CALL, 1, addr, 2), // re-entry at depth 1
            make_step_with_index(OP_SSTORE, 2, addr, 3),
        ];

        let depth = detect_reentrancy_depth(&steps);
        assert!(depth >= 1, "should detect re-entry depth >= 1, got {depth}");
    }

    // -- Pipeline metrics --

    #[test]
    fn pipeline_metrics_track_step_count() {
        struct NoopStep;
        impl AnalysisStep for NoopStep {
            fn name(&self) -> &'static str {
                "Noop"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                Ok(StepResult::Continue)
            }
        }

        let pipeline = AnalysisPipeline {
            steps: vec![Box::new(NoopStep), Box::new(NoopStep), Box::new(NoopStep)],
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        };

        let store = Store::new("test-metrics", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };
        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.5,
            priority: AlertPriority::Medium,
        };
        let config = AnalysisConfig {
            min_alert_confidence: 0.0,
            ..Default::default()
        };

        let (_result, metrics) = pipeline
            .analyze(&store, &block, &suspicion, &config)
            .unwrap();
        assert_eq!(metrics.steps_executed, 3);
        assert_eq!(metrics.steps_dismissed, 0);
        assert_eq!(metrics.step_durations.len(), 3);
    }

    #[test]
    fn pipeline_dynamic_step_after_dismiss_is_skipped() {
        struct AdderThenDismiss;
        impl AnalysisStep for AdderThenDismiss {
            fn name(&self) -> &'static str {
                "AdderThenDismiss"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                Ok(StepResult::Dismiss)
            }
        }

        struct UnreachableStep;
        impl AnalysisStep for UnreachableStep {
            fn name(&self) -> &'static str {
                "Unreachable"
            }
            fn execute(
                &self,
                _ctx: &mut AnalysisContext,
                _store: &Store,
                _block: &Block,
                _suspicion: &SuspiciousTx,
                _config: &AnalysisConfig,
            ) -> Result<StepResult, SentinelError> {
                panic!("should never run");
            }
        }

        let pipeline = AnalysisPipeline {
            steps: vec![
                Box::new(AdderThenDismiss),
                Box::new(UnreachableStep),
            ],
            anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
        };

        let store = Store::new("test-dismiss-skip", EngineType::InMemory).unwrap();
        let block = Block {
            header: Default::default(),
            body: Default::default(),
        };
        let suspicion = SuspiciousTx {
            tx_hash: H256::zero(),
            tx_index: 0,
            reasons: vec![],
            score: 0.5,
            priority: AlertPriority::Medium,
        };
        let config = AnalysisConfig::default();

        let (result, _) = pipeline
            .analyze(&store, &block, &suspicion, &config)
            .unwrap();
        assert!(result.is_none());
    }
}
