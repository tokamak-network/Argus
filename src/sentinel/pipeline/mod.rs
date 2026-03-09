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
pub use steps::{FundFlowAnalyzer, PatternMatcher};

// Re-export opcode constants for feature extraction (used by features + steps)
pub(crate) use crate::opcodes::{
    OP_CALL, OP_CALLCODE, OP_CREATE, OP_CREATE2, OP_DELEGATECALL, OP_LOG0, OP_LOG4, OP_REVERT,
    OP_SELFDESTRUCT, OP_SLOAD, OP_SSTORE, OP_STATICCALL,
};
