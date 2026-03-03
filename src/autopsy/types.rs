//! Core types for the autopsy analysis module.

use ethrex_common::{Address, U256};
use serde::{Deserialize, Serialize};

/// Detected attack pattern with evidence from the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackPattern {
    /// Re-entrant call detected: external call followed by state modification.
    Reentrancy {
        target_contract: Address,
        reentrant_call_step: usize,
        state_modified_step: usize,
        call_depth_at_entry: usize,
    },

    /// Flash loan pattern: large borrow early, repayment near end.
    FlashLoan {
        borrow_step: usize,
        borrow_amount: U256,
        repay_step: usize,
        repay_amount: U256,
        /// The flash loan provider contract (if detected via callback pattern).
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<Address>,
        /// The token involved (None = ETH, Some = ERC-20).
        #[serde(skip_serializing_if = "Option::is_none")]
        token: Option<Address>,
    },

    /// Price manipulation: oracle read → swap → oracle read with price delta.
    PriceManipulation {
        oracle_read_before: usize,
        swap_step: usize,
        oracle_read_after: usize,
        price_delta_percent: f64,
    },

    /// SSTORE without preceding access control check in same call frame.
    AccessControlBypass {
        sstore_step: usize,
        contract: Address,
    },
}

/// A single fund transfer detected in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundFlow {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    /// None = native ETH transfer, Some(addr) = ERC-20 token.
    pub token: Option<Address>,
    pub step_index: usize,
}

/// Detected pattern with confidence score and evidence chain.
///
/// Wraps an [`AttackPattern`] with a 0.0–1.0 confidence score and
/// a list of human-readable evidence strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedPattern {
    pub pattern: AttackPattern,
    /// Confidence score: 0.0 (low) to 1.0 (high).
    pub confidence: f64,
    /// Human-readable evidence supporting the detection.
    pub evidence: Vec<String>,
}

/// An annotated step with human-readable explanation.
#[derive(Debug, Clone, Serialize)]
pub struct AnnotatedStep {
    pub step_index: usize,
    pub annotation: String,
    pub severity: Severity,
}

/// Severity level for annotated steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}
