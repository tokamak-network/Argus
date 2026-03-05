//! AiClient trait + shared types + re-exports for LiteLLM and Anthropic backends.
//!
//! Primary backend: LiteLLM proxy (OpenAI-compatible `/v1/chat/completions`)
//! Fallback backend: Direct Anthropic Messages API

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::types::{AgentVerdict, AttackType};

pub mod anthropic_client;
pub mod litellm_client;

pub use anthropic_client::AnthropicClient;
pub use litellm_client::LiteLLMClient;

// ── Error ──────────────────────────────────────────────────────────────────

/// Errors from AI client operations.
#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("API error (status {status}): {message}")]
    Api { status: u16, message: String },
    #[error("No tool_use response from model")]
    NoToolResponse,
    #[error("Failed to parse verdict: {0}")]
    ParseError(String),
    #[error("API key not configured")]
    MissingApiKey,
    #[error("AgentContext too large ({size} bytes, max {max} bytes)")]
    ContextTooLarge { size: usize, max: usize },
}

// ── AiClient trait ─────────────────────────────────────────────────────────

/// Trait for AI backends. Allows swapping between LiteLLM, Anthropic direct, etc.
#[allow(async_fn_in_trait)]
pub trait AiClient: Send + Sync {
    /// Analyze a transaction and return a verdict.
    async fn judge(
        &self,
        context: &super::types::AgentContext,
        model: &str,
    ) -> Result<AiResponse, AiError>;
}

/// Response from an AI call, including verdict and usage metadata.
#[derive(Debug, Clone)]
pub struct AiResponse {
    pub verdict: AgentVerdict,
    pub usage: TokenUsage,
}

/// Token usage from an API call (for cost tracking).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub cache_creation_input_tokens: u32,
    pub cache_read_input_tokens: u32,
}

// ── Shared verdict parsing ───────────────────────────────────────────────

/// Parse a tool call's JSON arguments into an AgentVerdict.
pub(crate) fn parse_verdict(
    input: &Value,
    model: &str,
    tokens: u32,
    latency_ms: u64,
) -> Result<AgentVerdict, AiError> {
    let is_attack = input
        .get("is_attack")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| AiError::ParseError("missing is_attack".to_string()))?;

    let confidence = input
        .get("confidence")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| AiError::ParseError("missing confidence".to_string()))?
        .clamp(0.0, 1.0);

    let attack_type_str = input
        .get("attack_type")
        .and_then(|v| v.as_str())
        .unwrap_or("none");

    let attack_type = if is_attack && attack_type_str != "none" {
        Some(AttackType::from_str_lossy(attack_type_str))
    } else {
        None
    };

    let reasoning = input
        .get("reasoning")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let evidence = input
        .get("evidence")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let false_positive_reason = input
        .get("false_positive_reason")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(AgentVerdict {
        is_attack,
        confidence,
        attack_type,
        reasoning,
        evidence,
        evidence_valid: false, // Default false until Hallucination Guard verifies (Phase 1)
        false_positive_reason,
        model_used: model.to_string(),
        tokens_used: tokens,
        latency_ms,
    })
}

/// Build the verdict tool schema (shared between LiteLLM and Anthropic).
pub(crate) fn verdict_tool_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "is_attack": {
                "type": "boolean",
                "description": "Whether this transaction is an attack"
            },
            "confidence": {
                "type": "number",
                "description": "Confidence level 0.0-1.0"
            },
            "attack_type": {
                "type": "string",
                "description": "Attack type: reentrancy, flash_loan, price_manipulation, access_control, front_running, sandwich, or none"
            },
            "reasoning": {
                "type": "string",
                "description": "Detailed reasoning for the verdict"
            },
            "evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Key evidence items referencing actual AgentContext data"
            },
            "false_positive_reason": {
                "type": "string",
                "description": "If not an attack, explain why despite suspicious signals"
            }
        },
        "required": ["is_attack", "confidence", "attack_type", "reasoning", "evidence"]
    })
}

// ── Context size guard ───────────────────────────────────────────────────

/// Maximum serialized AgentContext size (256 KB). Prevents unbounded API spend
/// from adversarial TX traces with extremely deep call graphs or many storage mutations.
pub(crate) const MAX_CONTEXT_BYTES: usize = 256 * 1024;

/// Serialize context to JSON and reject if it exceeds the size limit.
/// Returns the JSON string on success.
pub(crate) fn serialize_context_checked(
    context: &super::types::AgentContext,
) -> Result<String, AiError> {
    let json = serde_json::to_string(context).map_err(|e| AiError::ParseError(e.to_string()))?;
    if json.len() > MAX_CONTEXT_BYTES {
        return Err(AiError::ContextTooLarge {
            size: json.len(),
            max: MAX_CONTEXT_BYTES,
        });
    }
    Ok(json)
}

// ── Cost calculation (pricing table) ─────────────────────────────────────

struct ModelPricing {
    keyword: &'static str,
    input: f64,
    output: f64,
    cache_write: f64,
    cache_read: f64,
}

const PRICING_TABLE: &[ModelPricing] = &[
    ModelPricing {
        keyword: "haiku",
        input: 1.0,
        output: 5.0,
        cache_write: 1.25,
        cache_read: 0.1,
    },
    ModelPricing {
        keyword: "sonnet",
        input: 3.0,
        output: 15.0,
        cache_write: 3.75,
        cache_read: 0.3,
    },
    ModelPricing {
        keyword: "flash",
        input: 0.15,
        output: 0.60,
        cache_write: 0.0,
        cache_read: 0.0,
    },
    ModelPricing {
        keyword: "gemini",
        input: 1.25,
        output: 10.0,
        cache_write: 0.0,
        cache_read: 0.0,
    },
    ModelPricing {
        keyword: "gpt-5",
        input: 2.50,
        output: 10.0,
        cache_write: 0.0,
        cache_read: 0.0,
    },
    ModelPricing {
        keyword: "deepseek",
        input: 0.27,
        output: 1.10,
        cache_write: 0.0,
        cache_read: 0.0,
    },
];

const DEFAULT_PRICING: (f64, f64, f64, f64) = (3.0, 15.0, 0.0, 0.0);

impl TokenUsage {
    /// Calculate cost in USD based on model pricing.
    ///
    /// Works with both LiteLLM model names (e.g. `anthropic/claude-haiku-4-5-20251001`)
    /// and bare model names (e.g. `claude-haiku-4-5-20251001`).
    pub fn cost_usd(&self, model: &str) -> f64 {
        let (input_price, output_price, cache_write_price, cache_read_price) = PRICING_TABLE
            .iter()
            .find(|p| model.contains(p.keyword))
            .map(|p| (p.input, p.output, p.cache_write, p.cache_read))
            .unwrap_or(DEFAULT_PRICING);

        let mtok = 1_000_000.0_f64;
        f64::from(self.input_tokens) * input_price / mtok
            + f64::from(self.output_tokens) * output_price / mtok
            + f64::from(self.cache_creation_input_tokens) * cache_write_price / mtok
            + f64::from(self.cache_read_input_tokens) * cache_read_price / mtok
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verdict_attack() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": 0.92,
            "attack_type": "reentrancy",
            "reasoning": "Re-entrant call detected",
            "evidence": ["CALL at depth 0 to attacker", "SSTORE in callback at depth 2"],
            "false_positive_reason": ""
        });

        let verdict = parse_verdict(&input, "claude-haiku-4-5-20251001", 500, 1200).unwrap();
        assert!(verdict.is_attack);
        assert!((verdict.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(verdict.attack_type, Some(AttackType::Reentrancy));
        assert_eq!(verdict.evidence.len(), 2);
        assert_eq!(verdict.tokens_used, 500);
        assert_eq!(verdict.latency_ms, 1200);
        assert!(verdict.false_positive_reason.is_none());
    }

    #[test]
    fn parse_verdict_benign() {
        let input = serde_json::json!({
            "is_attack": false,
            "confidence": 0.15,
            "attack_type": "none",
            "reasoning": "Normal DEX swap",
            "evidence": ["Single token transfer"],
            "false_positive_reason": "Standard Uniswap V2 swap pattern"
        });

        let verdict = parse_verdict(&input, "claude-haiku-4-5-20251001", 300, 800).unwrap();
        assert!(!verdict.is_attack);
        assert!(verdict.attack_type.is_none());
        assert_eq!(
            verdict.false_positive_reason,
            Some("Standard Uniswap V2 swap pattern".to_string())
        );
    }

    #[test]
    fn parse_verdict_missing_is_attack_fails() {
        let input = serde_json::json!({
            "confidence": 0.5,
            "attack_type": "none",
            "reasoning": "test",
            "evidence": []
        });

        let result = parse_verdict(&input, "test", 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_verdict_with_litellm_model_prefix() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": 0.88,
            "attack_type": "flash_loan",
            "reasoning": "Flash loan detected",
            "evidence": ["borrow event"]
        });

        let verdict =
            parse_verdict(&input, "anthropic/claude-haiku-4-5-20251001", 400, 900).unwrap();
        assert!(verdict.is_attack);
        assert_eq!(verdict.model_used, "anthropic/claude-haiku-4-5-20251001");
    }

    #[test]
    fn parse_verdict_clamps_confidence() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": 95.0,
            "attack_type": "reentrancy",
            "reasoning": "test",
            "evidence": []
        });
        let verdict = parse_verdict(&input, "test", 0, 0).unwrap();
        assert!((verdict.confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_verdict_clamps_negative_confidence() {
        let input = serde_json::json!({
            "is_attack": false,
            "confidence": -0.5,
            "attack_type": "none",
            "reasoning": "test",
            "evidence": []
        });
        let verdict = parse_verdict(&input, "test", 0, 0).unwrap();
        assert!((verdict.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_verdict_evidence_valid_defaults_false() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": 0.9,
            "attack_type": "reentrancy",
            "reasoning": "test",
            "evidence": ["some evidence"]
        });
        let verdict = parse_verdict(&input, "test", 0, 0).unwrap();
        assert!(!verdict.evidence_valid);
    }

    #[test]
    fn token_usage_cost_haiku() {
        let usage = TokenUsage {
            input_tokens: 2000,
            output_tokens: 500,
            cache_creation_input_tokens: 1000,
            cache_read_input_tokens: 0,
        };
        let cost = usage.cost_usd("claude-haiku-4-5-20251001");
        // 2000 * 1.0/1M + 500 * 5.0/1M + 1000 * 1.25/1M = 0.002 + 0.0025 + 0.00125 = 0.00575
        assert!((cost - 0.00575).abs() < 1e-10);
    }

    #[test]
    fn token_usage_cost_sonnet() {
        let usage = TokenUsage {
            input_tokens: 2000,
            output_tokens: 800,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 1000,
        };
        let cost = usage.cost_usd("claude-sonnet-4-6");
        // 2000 * 3.0/1M + 800 * 15.0/1M + 1000 * 0.3/1M = 0.006 + 0.012 + 0.0003 = 0.0183
        assert!((cost - 0.0183).abs() < 1e-10);
    }

    #[test]
    fn token_usage_cost_litellm_model_prefix() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        // LiteLLM model names have "anthropic/" prefix — cost_usd should still match
        let direct = usage.cost_usd("claude-haiku-4-5-20251001");
        let prefixed = usage.cost_usd("anthropic/claude-haiku-4-5-20251001");
        assert!(
            (direct - prefixed).abs() < 1e-10,
            "cost should be same with or without prefix"
        );
    }

    #[test]
    fn token_usage_cost_gemini_flash() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.cost_usd("gemini-3-flash");
        // "flash" matches before "gemini" in PRICING_TABLE
        // 1000 * 0.15/1M + 500 * 0.60/1M = 0.00015 + 0.0003 = 0.00045
        assert!((cost - 0.00045).abs() < 1e-10);
    }

    #[test]
    fn token_usage_cost_cache_hit_savings() {
        let with_cache = TokenUsage {
            input_tokens: 500,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 1500,
        };
        let without_cache = TokenUsage {
            input_tokens: 2000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cached_cost = with_cache.cost_usd("claude-haiku-4-5-20251001");
        let uncached_cost = without_cache.cost_usd("claude-haiku-4-5-20251001");
        assert!(
            cached_cost < uncached_cost,
            "cached {cached_cost} should be cheaper than uncached {uncached_cost}"
        );
    }

    // ── Mock HTTP / error path tests (Task #3) ──────────────────────────

    #[test]
    fn parse_verdict_invalid_json_is_attack_not_bool() {
        let input = serde_json::json!({"is_attack": "not_a_bool"});
        let result = parse_verdict(&input, "test", 0, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("is_attack"),
            "error should mention is_attack: {err_msg}"
        );
    }

    #[test]
    fn parse_verdict_missing_confidence_fails() {
        let input = serde_json::json!({
            "is_attack": true,
            "attack_type": "reentrancy",
            "reasoning": "test",
            "evidence": []
        });
        let result = parse_verdict(&input, "test", 0, 0);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("confidence"),
            "error should mention confidence: {err_msg}"
        );
    }

    #[test]
    fn parse_verdict_confidence_as_string_fails() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": "high",
            "attack_type": "reentrancy",
            "reasoning": "test",
            "evidence": []
        });
        let result = parse_verdict(&input, "test", 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_verdict_empty_object_fails() {
        let input = serde_json::json!({});
        let result = parse_verdict(&input, "test", 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn parse_verdict_missing_optional_fields_succeeds() {
        let input = serde_json::json!({
            "is_attack": false,
            "confidence": 0.1
        });
        let verdict = parse_verdict(&input, "test", 0, 0).unwrap();
        assert!(!verdict.is_attack);
        assert!(verdict.attack_type.is_none());
        assert!(verdict.reasoning.is_empty());
        assert!(verdict.evidence.is_empty());
        assert!(verdict.false_positive_reason.is_none());
    }

    #[test]
    fn parse_verdict_evidence_with_non_string_items_filtered() {
        let input = serde_json::json!({
            "is_attack": true,
            "confidence": 0.9,
            "attack_type": "reentrancy",
            "reasoning": "test",
            "evidence": ["valid", 42, null, "also valid", true]
        });
        let verdict = parse_verdict(&input, "test", 0, 0).unwrap();
        assert_eq!(verdict.evidence, vec!["valid", "also valid"]);
    }

    #[test]
    fn ai_error_variants_display() {
        let errors: Vec<AiError> = vec![
            AiError::Http("timeout".to_string()),
            AiError::Api {
                status: 429,
                message: "rate limited".to_string(),
            },
            AiError::NoToolResponse,
            AiError::ParseError("bad json".to_string()),
            AiError::MissingApiKey,
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "error display should not be empty");
        }
    }

    #[test]
    fn ai_error_http_contains_message() {
        let err = AiError::Http("connection refused".to_string());
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn ai_error_api_contains_status_and_message() {
        let err = AiError::Api {
            status: 429,
            message: "rate limited".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("429"), "should contain status code");
        assert!(msg.contains("rate limited"), "should contain message");
    }

    #[test]
    fn cost_usd_unknown_model_uses_default_pricing() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.cost_usd("unknown-future-model-v99");
        // Default: input 3.0, output 15.0 per MTok
        // 1000 * 3.0/1M + 500 * 15.0/1M = 0.003 + 0.0075 = 0.0105
        assert!(
            (cost - 0.0105).abs() < 1e-10,
            "unknown model should use default pricing, got {cost}"
        );
    }

    #[test]
    fn cost_usd_deepseek_model() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.cost_usd("deepseek-v3");
        // 1000 * 0.27/1M + 500 * 1.10/1M = 0.00027 + 0.00055 = 0.00082
        assert!((cost - 0.00082).abs() < 1e-10);
    }

    #[test]
    fn cost_usd_gpt5_model() {
        let usage = TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        };
        let cost = usage.cost_usd("gpt-5-turbo");
        // 1000 * 2.50/1M + 500 * 10.0/1M = 0.0025 + 0.005 = 0.0075
        assert!((cost - 0.0075).abs() < 1e-10);
    }

    #[test]
    fn verdict_tool_schema_has_required_fields() {
        let schema = verdict_tool_schema();
        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("schema should have required array");
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(required_strs.contains(&"is_attack"));
        assert!(required_strs.contains(&"confidence"));
        assert!(required_strs.contains(&"attack_type"));
        assert!(required_strs.contains(&"reasoning"));
        assert!(required_strs.contains(&"evidence"));
    }

    #[test]
    fn verdict_tool_schema_false_positive_reason_is_optional() {
        let schema = verdict_tool_schema();
        let required = schema
            .get("required")
            .and_then(|v| v.as_array())
            .expect("schema should have required array");
        let required_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            !required_strs.contains(&"false_positive_reason"),
            "false_positive_reason should be optional"
        );
    }

    // ── Context size guard tests ──────────────────────────────────────────

    use super::super::types::*;
    use ethrex_common::{Address, H256, U256};

    fn small_context() -> AgentContext {
        AgentContext {
            tx_hash: H256::from([1u8; 32]),
            block_number: 21_000_000,
            from: Address::from([0xAA; 20]),
            to: Some(Address::from([0xBB; 20])),
            value_wei: U256::zero(),
            gas_used: 100_000,
            succeeded: true,
            revert_count: 0,
            suspicious_score: 0.3,
            suspicion_reasons: vec![],
            call_graph: vec![],
            storage_mutations: vec![],
            erc20_transfers: vec![],
            eth_transfers: vec![],
            log_events: vec![],
            delegatecalls: vec![],
            contract_creations: vec![],
        }
    }

    #[test]
    fn serialize_context_checked_small_succeeds() {
        let ctx = small_context();
        let result = serialize_context_checked(&ctx);
        assert!(result.is_ok());
        assert!(result.unwrap().len() < MAX_CONTEXT_BYTES);
    }

    #[test]
    fn serialize_context_checked_oversized_rejected() {
        let mut ctx = small_context();
        // Fill call_graph with enough entries to exceed 256KB
        for i in 0..5000 {
            ctx.call_graph.push(CallFrame {
                depth: (i % 1024) as u16,
                caller: Address::from([0xCC; 20]),
                target: Address::from([0xDD; 20]),
                value: U256::from(i),
                input_selector: Some([0xAA, 0xBB, 0xCC, 0xDD]),
                input_size: 1000,
                output_size: 500,
                gas_used: 100_000,
                call_type: CallType::Call,
                reverted: false,
            });
        }
        let result = serialize_context_checked(&ctx);
        match result {
            Err(AiError::ContextTooLarge { size, max }) => {
                assert!(size > MAX_CONTEXT_BYTES);
                assert_eq!(max, MAX_CONTEXT_BYTES);
            }
            other => panic!("expected ContextTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn context_too_large_error_display() {
        let err = AiError::ContextTooLarge {
            size: 300_000,
            max: 262_144,
        };
        let msg = err.to_string();
        assert!(msg.contains("300000"), "should contain size: {msg}");
        assert!(msg.contains("262144"), "should contain max: {msg}");
    }
}
