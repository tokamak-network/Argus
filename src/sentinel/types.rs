//! Sentinel-specific types for the pre-filter, deep analysis, and alert system.

use ethrex_common::{Address, H256, U256};
use serde::{Deserialize, Serialize};

use crate::autopsy::types::{AttackPattern, DetectedPattern, FundFlow};

/// Configuration for the sentinel pre-filter.
#[derive(Debug, Clone)]
pub struct SentinelConfig {
    /// Minimum combined score to flag a TX as suspicious (default: 0.5).
    pub suspicion_threshold: f64,
    /// Minimum ETH value for high-value transfer heuristic (default: 1 ETH).
    pub min_value_wei: U256,
    /// Minimum gas for gas-related heuristics (default: 500_000).
    pub min_gas_used: u64,
    /// Minimum ERC-20 transfer count to flag (default: 5).
    pub min_erc20_transfers: usize,
    /// Gas ratio threshold for unusual-gas heuristic (default: 0.95).
    pub gas_ratio_threshold: f64,
    /// Minimum number of independent signal categories required to emit an alert (default: 2).
    pub min_independent_signals: usize,
    /// Multiplicative factor applied when a known contract is involved (default: 0.3).
    /// Lower values suppress known-protocol interactions more aggressively.
    pub relevance_factor: f64,
    /// Multiplicative discount for symmetric flash loan cash flow (default: 0.5).
    pub symmetry_discount: f64,
    /// Multiplicative discount for known-protocol flash loan MEV patterns (default: 0.15).
    /// Applied when FlashLoan + KnownContract + large ERC20 are all present.
    /// Set to 1.0 to disable.
    pub mev_flash_loan_factor: f64,
    /// Multiplicative discount for SelfDestruct + HighValueRevert MEV patterns (default: 0.25).
    /// Applied when SelfDestruct + HighValueRevert are present without FlashLoan.
    /// Set to 1.0 to disable.
    pub mev_selfdestruct_factor: f64,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            suspicion_threshold: 0.5,
            // 1 ETH = 10^18 wei
            min_value_wei: U256::from(1_000_000_000_000_000_000_u64),
            min_gas_used: 500_000,
            min_erc20_transfers: 5,
            gas_ratio_threshold: 0.95,
            min_independent_signals: 2,
            relevance_factor: 0.3,
            symmetry_discount: 0.5,
            mev_flash_loan_factor: 0.15,
            mev_selfdestruct_factor: 0.25,
        }
    }
}

/// A transaction flagged as suspicious by the pre-filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousTx {
    pub tx_hash: H256,
    pub tx_index: usize,
    pub reasons: Vec<SuspicionReason>,
    pub score: f64,
    pub priority: AlertPriority,
    /// Number of whitelist entries that matched addresses in this TX.
    #[serde(default)]
    pub whitelist_matches: u32,
}

/// Reason why a transaction was flagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SuspicionReason {
    /// Flash loan event signature detected in logs.
    FlashLoanSignature { provider_address: Address },
    /// High-value TX that reverted with significant gas usage.
    HighValueWithRevert { value_wei: U256, gas_used: u64 },
    /// Unusually many ERC-20 Transfer events in a single TX.
    MultipleErc20Transfers { count: usize },
    /// TX interacts with a known high-value DeFi contract.
    KnownContractInteraction { address: Address, label: String },
    /// Gas usage suspiciously close to gas limit (automated exploit script).
    UnusualGasPattern { gas_used: u64, gas_limit: u64 },
    /// Self-destruct indicators detected.
    SelfDestructDetected,
    /// Both price oracle and DEX interaction in same TX.
    PriceOracleWithSwap { oracle: Address },
    /// Flash loan funds flow to new/unknown addresses instead of being repaid symmetrically.
    AsymmetricCashFlow { unique_destinations: usize },
}

impl SuspicionReason {
    /// Fixed score contribution for this reason.
    pub fn score(&self) -> f64 {
        match self {
            Self::FlashLoanSignature { .. } => 0.4,
            Self::HighValueWithRevert { .. } => 0.3,
            Self::MultipleErc20Transfers { count } => {
                if *count > 10 {
                    0.4
                } else {
                    0.2
                }
            }
            Self::KnownContractInteraction { .. } => 0.0,
            Self::UnusualGasPattern { .. } => 0.15,
            Self::SelfDestructDetected => 0.3,
            Self::PriceOracleWithSwap { .. } => 0.2,
            Self::AsymmetricCashFlow { .. } => 0.2,
        }
    }
}

/// Alert priority derived from combined suspicion score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertPriority {
    /// Score >= 0.3 but < 0.65
    Medium,
    /// Score >= 0.65 but < 0.85
    High,
    /// Score >= 0.85
    Critical,
}

impl AlertPriority {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.85 {
            Self::Critical
        } else if score >= 0.65 {
            Self::High
        } else {
            Self::Medium
        }
    }
}

/// Configuration for the deep analysis engine.
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Maximum opcode steps to record before aborting (default: 1_000_000).
    pub max_steps: usize,
    /// Minimum confidence to emit a SentinelAlert (default: 0.4).
    pub min_alert_confidence: f64,
    /// When true, emit lightweight alerts from pre-filter results if deep
    /// analysis fails or returns nothing. Useful for monitoring mode without
    /// full Merkle Patricia Trie state (default: false).
    pub prefilter_alert_mode: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_steps: 1_000_000,
            min_alert_confidence: 0.4,
            prefilter_alert_mode: false,
        }
    }
}

/// Alert emitted after deep analysis confirms suspicious activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelAlert {
    pub block_number: u64,
    pub block_hash: H256,
    pub tx_hash: H256,
    pub tx_index: usize,
    pub alert_priority: AlertPriority,
    /// Pre-filter suspicion reasons that triggered deep analysis.
    pub suspicion_reasons: Vec<SuspicionReason>,
    /// Combined score: max(prefilter heuristic score, pipeline confidence).
    /// For alerts without pipeline analysis, this equals the prefilter score.
    pub suspicion_score: f64,
    /// Attack patterns confirmed by deep analysis.
    pub detected_patterns: Vec<DetectedPattern>,
    /// Fund flows extracted by deep analysis.
    pub fund_flows: Vec<FundFlow>,
    /// Total value at risk across all fund flows.
    pub total_value_at_risk: U256,
    /// Number of whitelist matches that contributed to score reduction.
    #[serde(default)]
    pub whitelist_matches: u32,
    /// Human-readable summary.
    pub summary: String,
    /// Number of opcode steps recorded during replay.
    pub total_steps: usize,
    /// Data quality indicator for the alert's underlying trace data.
    /// `None` for prefilter-only alerts (no replay), `Some(High)` for successful
    /// deep replay, `Some(Medium)` for receipt-based fallback, `Some(Low)` for
    /// partial/failed replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_quality: Option<crate::types::DataQuality>,
    /// Numerical feature vector extracted by the adaptive pipeline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_vector: Option<super::pipeline::FeatureVector>,
    /// AI agent verdict (populated asynchronously when ai_agent feature is enabled).
    #[cfg(feature = "ai_agent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_verdict: Option<super::ai::types::AgentVerdict>,
}

impl SentinelAlert {
    /// Highest confidence among all detected patterns.
    pub fn max_confidence(&self) -> f64 {
        self.detected_patterns
            .iter()
            .map(|p| p.confidence)
            .fold(0.0_f64, f64::max)
    }

    /// Names of all detected attack patterns.
    pub fn pattern_names(&self) -> Vec<&'static str> {
        self.detected_patterns
            .iter()
            .map(|p| match &p.pattern {
                AttackPattern::Reentrancy { .. } => "Reentrancy",
                AttackPattern::FlashLoan { .. } => "FlashLoan",
                AttackPattern::PriceManipulation { .. } => "PriceManipulation",
                AttackPattern::AccessControlBypass { .. } => "AccessControlBypass",
            })
            .collect()
    }
}

/// Errors specific to the sentinel deep analysis engine.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("VM execution error: {0}")]
    Vm(String),

    #[error("Database error: {0}")]
    Db(String),

    #[error("Block {block_number} not found in store")]
    BlockNotFound { block_number: u64 },

    #[error("Transaction at index {tx_index} not found in block {block_number}")]
    TxNotFound { block_number: u64, tx_index: usize },

    #[error("Parent block header not found for block {block_number}")]
    ParentNotFound { block_number: u64 },

    #[error("State root missing for block {block_number}")]
    StateRootMissing { block_number: u64 },

    #[error("Sender recovery failed for tx at index {tx_index}: {cause}")]
    SenderRecovery { tx_index: usize, cause: String },

    #[error("Step limit exceeded: {steps} > {max_steps}")]
    StepLimitExceeded { steps: usize, max_steps: usize },
}

// ---------------------------------------------------------------------------
// Mempool monitoring types
// ---------------------------------------------------------------------------

/// Alert emitted when a pending mempool transaction looks suspicious.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolAlert {
    /// Hash of the pending transaction.
    pub tx_hash: H256,
    /// Sender of the pending transaction.
    pub sender: Address,
    /// Target address (None for contract creation).
    pub target: Option<Address>,
    /// Reasons the transaction was flagged.
    pub reasons: Vec<MempoolSuspicionReason>,
    /// Combined suspicion score.
    pub score: f64,
}

/// Reason why a mempool transaction was flagged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MempoolSuspicionReason {
    /// Calldata starts with a known flash-loan function selector.
    FlashLoanSelector { selector: [u8; 4] },
    /// High-value TX targeting a known DeFi contract.
    HighValueDeFi { value_wei: U256, target: Address },
    /// High gas + known DeFi contract interaction.
    HighGasKnownContract { gas_limit: u64, target: Address },
    /// Contract creation with unusually large init code.
    SuspiciousContractCreation { init_code_size: usize },
    /// Multicall pattern on a known DeFi router.
    MulticallPattern { target: Address },
}

impl MempoolSuspicionReason {
    /// Fixed score contribution for this reason.
    pub fn score(&self) -> f64 {
        match self {
            Self::FlashLoanSelector { .. } => 0.4,
            Self::HighValueDeFi { .. } => 0.3,
            Self::HighGasKnownContract { .. } => 0.2,
            Self::SuspiciousContractCreation { .. } => 0.25,
            Self::MulticallPattern { .. } => 0.3,
        }
    }
}
