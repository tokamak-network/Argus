//! Deep analysis engine for the sentinel.
//!
//! When the pre-filter flags a transaction as suspicious, the deep analyzer
//! re-executes it with full opcode recording and runs the autopsy pipeline:
//! AttackClassifier, FundFlowTracer, and report generation.

use ethrex_common::U256;
use ethrex_common::types::Block;
use ethrex_storage::Store;

#[cfg(feature = "autopsy")]
use crate::autopsy::classifier::AttackClassifier;
#[cfg(feature = "autopsy")]
use crate::autopsy::fund_flow::FundFlowTracer;
#[cfg(feature = "autopsy")]
use crate::autopsy::types::FundFlow;

use super::pipeline::AnalysisPipeline;
use super::replay::replay_tx_from_store;
use super::types::{AlertPriority, AnalysisConfig, SentinelAlert, SentinelError, SuspiciousTx};

/// Stateless deep analysis engine.
///
/// Re-executes suspicious transactions and runs the autopsy pipeline to confirm
/// or dismiss the pre-filter's suspicion.
pub struct DeepAnalyzer;

impl DeepAnalyzer {
    /// Analyze a suspicious transaction by replaying it with opcode recording.
    ///
    /// If an `AnalysisPipeline` is provided, delegates to the adaptive pipeline.
    /// Otherwise, falls back to the legacy fixed analysis flow.
    ///
    /// Returns `Some(SentinelAlert)` if the deep analysis confirms suspicious
    /// patterns above the configured confidence threshold. Returns `None` if
    /// the transaction turns out to be benign after deep analysis.
    pub fn analyze(
        store: &Store,
        block: &Block,
        suspicion: &SuspiciousTx,
        config: &AnalysisConfig,
        pipeline: Option<&AnalysisPipeline>,
    ) -> Result<Option<SentinelAlert>, SentinelError> {
        // If an adaptive pipeline is provided, delegate to it
        if let Some(pipeline) = pipeline {
            let (alert, _metrics) = pipeline.analyze(store, block, suspicion, config)?;
            return Ok(alert);
        }

        let block_number = block.header.number;
        let block_hash = block.header.hash();

        // Step 1: Replay the transaction with opcode recording
        let replay_result = replay_tx_from_store(store, block, suspicion.tx_index, config)?;

        let steps = &replay_result.trace.steps;
        let total_steps = steps.len();

        // Step 2: Run attack classifier
        #[cfg(feature = "autopsy")]
        let detected_patterns = AttackClassifier::classify_with_confidence(steps);
        #[cfg(not(feature = "autopsy"))]
        let detected_patterns_count = 0usize;

        // Step 3: Run fund flow tracer
        #[cfg(feature = "autopsy")]
        let fund_flows = FundFlowTracer::trace(steps);
        #[cfg(not(feature = "autopsy"))]
        let fund_flows_value = U256::zero();

        // Step 4: Compute total value at risk
        #[cfg(feature = "autopsy")]
        let total_value_at_risk = compute_total_value(&fund_flows);
        #[cfg(not(feature = "autopsy"))]
        let total_value_at_risk = fund_flows_value;

        // Step 5: Determine if the deep analysis confirms the suspicion
        #[cfg(feature = "autopsy")]
        let max_confidence = detected_patterns
            .iter()
            .map(|p| p.confidence)
            .fold(0.0_f64, f64::max);
        #[cfg(not(feature = "autopsy"))]
        let max_confidence = 0.0_f64;

        // If no patterns detected with sufficient confidence, dismiss
        #[cfg(feature = "autopsy")]
        let has_confirmed_patterns =
            !detected_patterns.is_empty() && max_confidence >= config.min_alert_confidence;
        #[cfg(not(feature = "autopsy"))]
        let has_confirmed_patterns = detected_patterns_count > 0;

        if !has_confirmed_patterns {
            return Ok(None);
        }

        // Step 6: Generate summary and alert
        #[cfg(feature = "autopsy")]
        let summary = generate_summary(&detected_patterns, total_value_at_risk, block_number);
        #[cfg(not(feature = "autopsy"))]
        let summary = format!(
            "Suspicious activity in block {block_number}, tx index {}",
            suspicion.tx_index
        );

        // Determine alert priority from both pre-filter score and deep analysis confidence
        let combined_score = suspicion.score.max(max_confidence);
        let alert_priority = AlertPriority::from_score(combined_score);

        let alert = SentinelAlert {
            block_number,
            block_hash,
            tx_hash: suspicion.tx_hash,
            tx_index: suspicion.tx_index,
            alert_priority,
            suspicion_reasons: suspicion.reasons.clone(),
            suspicion_score: suspicion.score,
            #[cfg(feature = "autopsy")]
            detected_patterns,
            #[cfg(feature = "autopsy")]
            fund_flows,
            total_value_at_risk,
            summary,
            total_steps,
            feature_vector: None,
        };

        Ok(Some(alert))
    }
}

/// Compute total value at risk across all fund flows (ETH only for now).
#[cfg(feature = "autopsy")]
fn compute_total_value(flows: &[FundFlow]) -> U256 {
    flows
        .iter()
        .filter(|f| f.token.is_none()) // Only count native ETH
        .fold(U256::zero(), |acc, f| acc.saturating_add(f.value))
}

/// Generate a human-readable summary from deep analysis results.
#[cfg(feature = "autopsy")]
fn generate_summary(
    patterns: &[crate::autopsy::types::DetectedPattern],
    total_value: U256,
    block_number: u64,
) -> String {
    use crate::autopsy::types::AttackPattern;

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
