//! TOML-compatible configuration for the AI agent `[ai]` section.

use super::circuit_breaker::CircuitBreaker;
use super::rate_limit::HourlyRateTracker;
use super::types::CostTracker;

/// TOML-compatible configuration for the `[ai]` section.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct AiConfig {
    /// Master switch for AI agent.
    pub enabled: bool,
    /// Backend type: "litellm" or "anthropic".
    pub backend: String,

    /// Environment variable name holding the Anthropic API key.
    pub anthropic_api_key_env: String,

    /// LiteLLM proxy base URL (only when backend = "litellm").
    pub litellm_api_base: Option<String>,
    /// Environment variable name holding the LiteLLM API key.
    pub litellm_api_key_env: Option<String>,

    /// Model for screening (tier-1).
    pub screening_model: String,
    /// Model for deep analysis (tier-2).
    pub deep_model: String,

    /// Confidence threshold for escalation from screening to deep model.
    pub is_suspicious_confidence_threshold: f64,

    pub monthly_budget_usd: f64,
    pub daily_limit_usd: f64,
    pub hourly_rate_limit: u32,
    pub max_concurrent_per_block: u8,
    pub request_timeout_secs: u64,
    pub max_retries: u32,
    pub max_context_tokens: u32,

    /// Circuit breaker: consecutive failure threshold.
    pub circuit_breaker_threshold: u32,
    /// Circuit breaker: cooldown seconds after tripping.
    pub circuit_breaker_cooldown_secs: u64,

    /// Path for CostTracker JSON persistence file.
    pub cost_tracker_path: Option<String>,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: "litellm".to_string(),
            anthropic_api_key_env: "ANTHROPIC_API_KEY".to_string(),
            litellm_api_base: None,
            litellm_api_key_env: None,
            screening_model: "gemini-3-flash".to_string(),
            deep_model: "gemini-3-pro".to_string(),
            is_suspicious_confidence_threshold: 0.6,
            monthly_budget_usd: 150.0,
            daily_limit_usd: 10.0,
            hourly_rate_limit: 100,
            max_concurrent_per_block: 3,
            request_timeout_secs: 30,
            max_retries: 3,
            max_context_tokens: 4000,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 600,
            cost_tracker_path: None,
        }
    }
}

impl AiConfig {
    /// Validate configuration, returning an error message on failure.
    pub fn validate(&self) -> Result<(), String> {
        if self.is_suspicious_confidence_threshold < 0.0
            || self.is_suspicious_confidence_threshold > 1.0
        {
            return Err(format!(
                "ai.is_suspicious_confidence_threshold must be in [0.0, 1.0], got {}",
                self.is_suspicious_confidence_threshold
            ));
        }
        if self.monthly_budget_usd < 0.0 {
            return Err("ai.monthly_budget_usd must be non-negative".to_string());
        }
        if self.daily_limit_usd < 0.0 {
            return Err("ai.daily_limit_usd must be non-negative".to_string());
        }
        if self.hourly_rate_limit == 0 {
            return Err("ai.hourly_rate_limit must be > 0".to_string());
        }
        if self.max_concurrent_per_block == 0 {
            return Err("ai.max_concurrent_per_block must be > 0".to_string());
        }
        if self.request_timeout_secs == 0 {
            return Err("ai.request_timeout_secs must be > 0".to_string());
        }
        if self.circuit_breaker_threshold == 0 {
            return Err("ai.circuit_breaker_threshold must be > 0".to_string());
        }
        if !matches!(self.backend.as_str(), "litellm" | "anthropic") {
            return Err(format!(
                "ai.backend must be 'litellm' or 'anthropic', got '{}'",
                self.backend
            ));
        }

        self.validate_api_key()?;

        Ok(())
    }

    /// Check that the required API key environment variable is set.
    fn validate_api_key(&self) -> Result<(), String> {
        match self.backend.as_str() {
            "anthropic" => {
                if std::env::var(&self.anthropic_api_key_env).is_err() {
                    return Err(format!(
                        "Environment variable '{}' is not set (required for anthropic backend)",
                        self.anthropic_api_key_env
                    ));
                }
            }
            "litellm" => {
                let key_env = self
                    .litellm_api_key_env
                    .as_deref()
                    .unwrap_or("LITELLM_API_KEY");
                if std::env::var(key_env).is_err() {
                    return Err(format!(
                        "Environment variable '{}' is not set (required for litellm backend)",
                        key_env
                    ));
                }
                if self.litellm_api_base.is_none() && std::env::var("LITELLM_BASE_URL").is_err() {
                    return Err(
                        "Either ai.litellm_api_base or LITELLM_BASE_URL must be set".to_string()
                    );
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Build a CostTracker with this config's budget values.
    pub fn to_cost_tracker(&self) -> CostTracker {
        CostTracker {
            monthly_budget_usd: self.monthly_budget_usd,
            daily_limit_usd: self.daily_limit_usd,
            hourly_rate_limit: self.hourly_rate_limit,
            max_concurrent_per_block: self.max_concurrent_per_block,
            ..CostTracker::default()
        }
    }

    /// Build a CircuitBreaker from this config.
    pub fn to_circuit_breaker(&self) -> CircuitBreaker {
        CircuitBreaker::new(
            self.circuit_breaker_threshold,
            self.circuit_breaker_cooldown_secs,
        )
    }

    /// Build an HourlyRateTracker from this config.
    pub fn to_hourly_tracker(&self) -> HourlyRateTracker {
        HourlyRateTracker::new(self.hourly_rate_limit)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_config_default_values() {
        let config = AiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.backend, "litellm");
        assert_eq!(config.monthly_budget_usd, 150.0);
        assert_eq!(config.daily_limit_usd, 10.0);
        assert_eq!(config.hourly_rate_limit, 100);
        assert_eq!(config.circuit_breaker_threshold, 5);
    }

    #[test]
    fn ai_config_validate_bad_threshold() {
        let mut config = AiConfig::default();
        config.is_suspicious_confidence_threshold = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_bad_backend() {
        let mut config = AiConfig::default();
        config.backend = "openai".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_to_cost_tracker() {
        let config = AiConfig {
            monthly_budget_usd: 200.0,
            daily_limit_usd: 15.0,
            hourly_rate_limit: 50,
            max_concurrent_per_block: 5,
            ..Default::default()
        };
        let tracker = config.to_cost_tracker();
        assert_eq!(tracker.monthly_budget_usd, 200.0);
        assert_eq!(tracker.daily_limit_usd, 15.0);
        assert_eq!(tracker.hourly_rate_limit, 50);
        assert_eq!(tracker.max_concurrent_per_block, 5);
    }

    #[test]
    fn ai_config_to_circuit_breaker() {
        let config = AiConfig {
            circuit_breaker_threshold: 10,
            circuit_breaker_cooldown_secs: 300,
            ..Default::default()
        };
        let cb = config.to_circuit_breaker();
        assert!(!cb.is_open());
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn ai_config_toml_roundtrip() {
        let config = AiConfig {
            enabled: true,
            backend: "litellm".to_string(),
            screening_model: "gemini-3-flash".to_string(),
            deep_model: "gemini-3-pro".to_string(),
            monthly_budget_usd: 200.0,
            ..Default::default()
        };
        let serialized = toml::to_string(&config).expect("serialize");
        let deserialized: AiConfig = toml::from_str(&serialized).expect("deserialize");
        assert!(deserialized.enabled);
        assert_eq!(deserialized.backend, "litellm");
        assert_eq!(deserialized.monthly_budget_usd, 200.0);
    }
}
