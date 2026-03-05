//! Adaptive multi-step analysis pipeline for the sentinel.
//!
//! Replaces the fixed `DeepAnalyzer` flow with a dynamic pipeline that can
//! skip, add, or reorder steps at runtime. Each step implements the
//! `AnalysisStep` trait and can early-exit (dismiss) or inject follow-up steps.

mod context;
mod features;
mod orchestrator;
mod steps;

#[cfg(test)]
mod tests;

// Re-export public API so `use crate::sentinel::pipeline::*` still works.
pub use context::{AnalysisContext, AnalysisStep, StepResult};
pub use features::{FeatureVector, detect_reentrancy_depth};
pub use orchestrator::{AnalysisPipeline, PipelineMetrics};
pub use steps::{AnomalyDetector, ConfidenceScorer, ReportGenerator, TraceAnalyzer};
#[cfg(feature = "autopsy")]
pub use steps::{FundFlowAnalyzer, PatternMatcher};

// Opcode constants for feature extraction (used by features + steps)
pub(crate) const OP_SLOAD: u8 = 0x54;
pub(crate) const OP_SSTORE: u8 = 0x55;
pub(crate) const OP_CALL: u8 = 0xF1;
pub(crate) const OP_CALLCODE: u8 = 0xF2;
pub(crate) const OP_DELEGATECALL: u8 = 0xF4;
pub(crate) const OP_CREATE: u8 = 0xF0;
pub(crate) const OP_CREATE2: u8 = 0xF5;
pub(crate) const OP_STATICCALL: u8 = 0xFA;
pub(crate) const OP_SELFDESTRUCT: u8 = 0xFF;
pub(crate) const OP_REVERT: u8 = 0xFD;
pub(crate) const OP_LOG0: u8 = 0xA0;
pub(crate) const OP_LOG4: u8 = 0xA4;
