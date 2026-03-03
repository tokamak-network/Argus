//! TOML-compatible configuration for the Sentinel system.
//!
//! `SentinelFullConfig` aggregates all sentinel sub-configurations into a single
//! TOML-deserializable struct. Operator-facing primitives (floats, integers, bools)
//! are used instead of domain types like `U256` so the config file stays readable.
//!
//! ```toml
//! [sentinel]
//! enabled = true
//!
//! [sentinel.prefilter]
//! suspicion_threshold = 0.5
//! min_value_eth = 1.0
//! min_gas_used = 500000
//! ```

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::types::{AnalysisConfig, SentinelConfig};

/// Top-level sentinel configuration, loadable from a TOML file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SentinelFullConfig {
    /// Master switch — sentinel is only started when `true`.
    pub enabled: bool,
    /// Pre-filter heuristic thresholds.
    pub prefilter: PrefilterConfig,
    /// Deep analysis engine settings.
    pub analysis: AnalysisTomlConfig,
    /// Alert output destinations.
    pub alert: AlertOutputConfig,
    /// Mempool monitoring (H-6b placeholder).
    pub mempool: MempoolMonitorConfig,
    /// Auto-pause circuit breaker (H-6d placeholder).
    pub auto_pause: AutoPauseConfig,
    /// Adaptive ML pipeline (H-6c placeholder).
    pub pipeline: AdaptivePipelineConfig,
}

impl SentinelFullConfig {
    /// Convert the TOML-facing pre-filter config into the domain type.
    pub fn to_sentinel_config(&self) -> SentinelConfig {
        let min_value_wei = ethrex_common::U256::from(
            (self.prefilter.min_value_eth * 1_000_000_000_000_000_000.0) as u128,
        );
        SentinelConfig {
            suspicion_threshold: self.prefilter.suspicion_threshold,
            min_value_wei,
            min_gas_used: self.prefilter.min_gas_used,
            min_erc20_transfers: self.prefilter.min_erc20_transfers,
            gas_ratio_threshold: self.prefilter.gas_ratio_threshold,
        }
    }

    /// Convert the TOML-facing analysis config into the domain type.
    pub fn to_analysis_config(&self) -> AnalysisConfig {
        AnalysisConfig {
            max_steps: self.analysis.max_steps,
            min_alert_confidence: self.analysis.min_alert_confidence,
            prefilter_alert_mode: self.analysis.prefilter_alert_mode,
        }
    }

    /// Validate configuration values, returning an error message on failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.prefilter.suspicion_threshold < 0.0 || self.prefilter.suspicion_threshold > 1.0 {
            return Err(format!(
                "prefilter.suspicion_threshold must be in [0.0, 1.0], got {}",
                self.prefilter.suspicion_threshold
            ));
        }
        if self.prefilter.gas_ratio_threshold < 0.0 || self.prefilter.gas_ratio_threshold > 1.0 {
            return Err(format!(
                "prefilter.gas_ratio_threshold must be in [0.0, 1.0], got {}",
                self.prefilter.gas_ratio_threshold
            ));
        }
        if self.prefilter.min_value_eth < 0.0 {
            return Err(format!(
                "prefilter.min_value_eth must be non-negative, got {}",
                self.prefilter.min_value_eth
            ));
        }
        if self.analysis.min_alert_confidence < 0.0 || self.analysis.min_alert_confidence > 1.0 {
            return Err(format!(
                "analysis.min_alert_confidence must be in [0.0, 1.0], got {}",
                self.analysis.min_alert_confidence
            ));
        }
        if self.analysis.max_steps == 0 {
            return Err("analysis.max_steps must be > 0".to_string());
        }
        if self.alert.rate_limit_per_minute == 0 {
            return Err("alert.rate_limit_per_minute must be > 0".to_string());
        }
        if self.auto_pause.confidence_threshold < 0.0
            || self.auto_pause.confidence_threshold > 1.0
        {
            return Err(format!(
                "auto_pause.confidence_threshold must be in [0.0, 1.0], got {}",
                self.auto_pause.confidence_threshold
            ));
        }
        Ok(())
    }
}

/// Pre-filter heuristic thresholds (TOML-friendly).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrefilterConfig {
    /// Minimum combined score to flag a TX (default: 0.5).
    pub suspicion_threshold: f64,
    /// Minimum ETH value for high-value transfer heuristic (default: 1.0 ETH).
    pub min_value_eth: f64,
    /// Minimum gas for gas-related heuristics (default: 500_000).
    pub min_gas_used: u64,
    /// Minimum ERC-20 transfer count to flag (default: 5).
    pub min_erc20_transfers: usize,
    /// Gas ratio threshold for unusual-gas heuristic (default: 0.95).
    pub gas_ratio_threshold: f64,
}

impl Default for PrefilterConfig {
    fn default() -> Self {
        Self {
            suspicion_threshold: 0.5,
            min_value_eth: 1.0,
            min_gas_used: 500_000,
            min_erc20_transfers: 5,
            gas_ratio_threshold: 0.95,
        }
    }
}

/// Deep analysis engine settings (TOML-friendly).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AnalysisTomlConfig {
    /// Maximum opcode steps before aborting (default: 1_000_000).
    pub max_steps: usize,
    /// Minimum confidence to emit a SentinelAlert (default: 0.4).
    pub min_alert_confidence: f64,
    /// Emit lightweight alerts from pre-filter when deep analysis is unavailable.
    pub prefilter_alert_mode: bool,
}

impl Default for AnalysisTomlConfig {
    fn default() -> Self {
        let ac = AnalysisConfig::default();
        Self {
            max_steps: ac.max_steps,
            min_alert_confidence: ac.min_alert_confidence,
            prefilter_alert_mode: ac.prefilter_alert_mode,
        }
    }
}

/// Alert output configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertOutputConfig {
    /// Path for JSONL alert file (None = disabled).
    pub jsonl_path: Option<PathBuf>,
    /// Webhook URL for HTTP POST alerts (None = disabled).
    pub webhook_url: Option<String>,
    /// Maximum alerts per minute (default: 30).
    pub rate_limit_per_minute: usize,
    /// Block window for deduplication (default: 10).
    pub dedup_window_blocks: u64,
}

impl Default for AlertOutputConfig {
    fn default() -> Self {
        Self {
            jsonl_path: None,
            webhook_url: None,
            rate_limit_per_minute: 30,
            dedup_window_blocks: 10,
        }
    }
}

/// Mempool monitoring configuration (H-6b placeholder).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MempoolMonitorConfig {
    /// Enable mempool monitoring (default: false).
    pub enabled: bool,
    /// Minimum ETH value for mempool scanning (default: 10.0 ETH).
    pub min_value_eth: f64,
    /// Minimum gas limit for mempool scanning (default: 500_000).
    pub min_gas: u64,
}

impl Default for MempoolMonitorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_value_eth: 10.0,
            min_gas: 500_000,
        }
    }
}

/// Auto-pause circuit breaker configuration (H-6d placeholder).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoPauseConfig {
    /// Enable auto-pause on critical alerts (default: false).
    pub enabled: bool,
    /// Minimum confidence to trigger pause (default: 0.9).
    pub confidence_threshold: f64,
    /// Minimum alert priority to trigger pause (default: "Critical").
    pub priority_threshold: String,
}

impl Default for AutoPauseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            confidence_threshold: 0.9,
            priority_threshold: "Critical".to_string(),
        }
    }
}

/// Adaptive ML pipeline configuration (H-6c placeholder).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdaptivePipelineConfig {
    /// Enable adaptive ML-based pre-filter (default: false).
    pub enabled: bool,
    /// Path to the ONNX model file (None = use rule-based).
    pub model_path: Option<PathBuf>,
    /// Maximum pipeline latency budget in milliseconds (default: 100).
    pub max_pipeline_ms: u64,
}

impl Default for AdaptivePipelineConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            model_path: None,
            max_pipeline_ms: 100,
        }
    }
}

/// Load a `SentinelFullConfig` from an optional TOML file path.
///
/// If `path` is `None`, returns the default config.
/// If the file cannot be read or parsed, returns an error string.
pub fn load_config(path: Option<&PathBuf>) -> Result<SentinelFullConfig, String> {
    let Some(path) = path else {
        return Ok(SentinelFullConfig::default());
    };

    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read sentinel config from {}: {}", path.display(), e))?;

    let wrapper: TomlWrapper = toml::from_str(&contents)
        .map_err(|e| format!("Failed to parse sentinel TOML config: {e}"))?;

    let config = wrapper.sentinel.unwrap_or_default();
    config.validate()?;
    Ok(config)
}

/// Wrapper for the top-level TOML structure: `[sentinel]` table.
#[derive(Debug, Deserialize)]
struct TomlWrapper {
    sentinel: Option<SentinelFullConfig>,
}

/// Merge CLI overrides into a loaded (or default) config.
///
/// CLI flags take precedence over TOML values.
pub fn merge_cli_overrides(
    config: &SentinelFullConfig,
    cli_enabled: Option<bool>,
    cli_alert_file: Option<&PathBuf>,
    cli_auto_pause: Option<bool>,
    cli_mempool: Option<bool>,
    cli_webhook_url: Option<&str>,
) -> SentinelFullConfig {
    let mut merged = config.clone();

    if let Some(enabled) = cli_enabled {
        merged.enabled = enabled;
    }
    if let Some(path) = cli_alert_file {
        merged.alert.jsonl_path = Some(path.clone());
    }
    if let Some(auto_pause) = cli_auto_pause {
        merged.auto_pause.enabled = auto_pause;
    }
    if let Some(mempool) = cli_mempool {
        merged.mempool.enabled = mempool;
    }
    if let Some(url) = cli_webhook_url {
        merged.alert.webhook_url = Some(url.to_string());
    }

    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_disabled() {
        let config = SentinelFullConfig::default();
        assert!(!config.enabled);
        assert!(!config.mempool.enabled);
        assert!(!config.auto_pause.enabled);
        assert!(!config.pipeline.enabled);
    }

    #[test]
    fn default_config_validates() {
        let config = SentinelFullConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn toml_roundtrip() {
        let config = SentinelFullConfig {
            enabled: true,
            prefilter: PrefilterConfig {
                suspicion_threshold: 0.3,
                min_value_eth: 5.0,
                ..Default::default()
            },
            alert: AlertOutputConfig {
                jsonl_path: Some(PathBuf::from("/tmp/alerts.jsonl")),
                rate_limit_per_minute: 10,
                ..Default::default()
            },
            ..Default::default()
        };

        let serialized = toml::to_string(&config).expect("serialize");
        let deserialized: SentinelFullConfig = toml::from_str(&serialized).expect("deserialize");

        assert!(deserialized.enabled);
        assert!((deserialized.prefilter.suspicion_threshold - 0.3).abs() < f64::EPSILON);
        assert!((deserialized.prefilter.min_value_eth - 5.0).abs() < f64::EPSILON);
        assert_eq!(
            deserialized.alert.jsonl_path,
            Some(PathBuf::from("/tmp/alerts.jsonl"))
        );
        assert_eq!(deserialized.alert.rate_limit_per_minute, 10);
    }

    #[test]
    fn toml_deserialization_with_sentinel_wrapper() {
        let toml_str = r#"
[sentinel]
enabled = true

[sentinel.prefilter]
suspicion_threshold = 0.4
min_value_eth = 2.0
min_gas_used = 300000

[sentinel.alert]
rate_limit_per_minute = 20
dedup_window_blocks = 5
"#;

        let wrapper: TomlWrapper = toml::from_str(toml_str).expect("parse");
        let config = wrapper.sentinel.expect("sentinel section");

        assert!(config.enabled);
        assert!((config.prefilter.suspicion_threshold - 0.4).abs() < f64::EPSILON);
        assert!((config.prefilter.min_value_eth - 2.0).abs() < f64::EPSILON);
        assert_eq!(config.prefilter.min_gas_used, 300_000);
        assert_eq!(config.alert.rate_limit_per_minute, 20);
        assert_eq!(config.alert.dedup_window_blocks, 5);
    }

    #[test]
    fn to_sentinel_config_converts_eth_to_wei() {
        let config = SentinelFullConfig {
            prefilter: PrefilterConfig {
                min_value_eth: 1.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let sentinel_config = config.to_sentinel_config();
        let expected_wei = ethrex_common::U256::from(1_000_000_000_000_000_000_u64);
        assert_eq!(sentinel_config.min_value_wei, expected_wei);
        assert!((sentinel_config.suspicion_threshold - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn to_analysis_config_preserves_values() {
        let config = SentinelFullConfig {
            analysis: AnalysisTomlConfig {
                max_steps: 500_000,
                min_alert_confidence: 0.7,
                prefilter_alert_mode: true,
            },
            ..Default::default()
        };

        let analysis = config.to_analysis_config();
        assert_eq!(analysis.max_steps, 500_000);
        assert!((analysis.min_alert_confidence - 0.7).abs() < f64::EPSILON);
        assert!(analysis.prefilter_alert_mode);
    }

    #[test]
    fn validate_rejects_invalid_threshold() {
        let config = SentinelFullConfig {
            prefilter: PrefilterConfig {
                suspicion_threshold: 1.5,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = SentinelFullConfig {
            prefilter: PrefilterConfig {
                suspicion_threshold: -0.1,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_max_steps() {
        let config = SentinelFullConfig {
            analysis: AnalysisTomlConfig {
                max_steps: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_rate_limit() {
        let config = SentinelFullConfig {
            alert: AlertOutputConfig {
                rate_limit_per_minute: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn cli_override_merging() {
        let base = SentinelFullConfig::default();
        let merged = merge_cli_overrides(
            &base,
            Some(true),
            Some(&PathBuf::from("/var/log/sentinel.jsonl")),
            Some(true),
            Some(true),
            Some("https://hooks.example.com/alert"),
        );

        assert!(merged.enabled);
        assert_eq!(
            merged.alert.jsonl_path,
            Some(PathBuf::from("/var/log/sentinel.jsonl"))
        );
        assert!(merged.auto_pause.enabled);
        assert!(merged.mempool.enabled);
        assert_eq!(
            merged.alert.webhook_url,
            Some("https://hooks.example.com/alert".to_string())
        );
    }

    #[test]
    fn load_config_returns_default_when_no_path() {
        let config = load_config(None).expect("should return default");
        assert!(!config.enabled);
        assert!(config.validate().is_ok());
    }
}
