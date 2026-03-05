//! Direct Anthropic Messages API client (fallback backend).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

use super::super::types::AgentContext;
use super::{AiClient, AiError, AiResponse, TokenUsage, parse_verdict, serialize_context_checked, verdict_tool_schema};

// ── Anthropic API types (request) ────────────────────────────────────────

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    system: Vec<SystemBlock>,
    messages: Vec<ChatMessage>,
    tools: Vec<AnthropicToolDef>,
    tool_choice: AnthropicToolChoice,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct SystemBlock {
    #[serde(rename = "type")]
    type_: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_control: Option<CacheControl>,
}

#[derive(Serialize)]
struct CacheControl {
    #[serde(rename = "type")]
    type_: String,
}

#[derive(Serialize)]
struct AnthropicToolDef {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Serialize)]
struct AnthropicToolChoice {
    #[serde(rename = "type")]
    type_: String,
    name: String,
}

// ── Anthropic API types (response) ───────────────────────────────────────

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
    usage: AnthropicUsage,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum AnthropicContentBlock {
    #[serde(rename = "text")]
    Text {
        #[allow(dead_code)]
        text: String,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        #[allow(dead_code)]
        id: String,
        #[allow(dead_code)]
        name: String,
        input: Value,
    },
}

#[derive(Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
    #[serde(default)]
    cache_creation_input_tokens: Option<u32>,
    #[serde(default)]
    cache_read_input_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct AnthropicErrorResponse {
    error: Option<AnthropicErrorDetail>,
}

#[derive(Deserialize)]
struct AnthropicErrorDetail {
    message: String,
}

// ── AnthropicClient ──────────────────────────────────────────────────────

/// Direct Anthropic Messages API client using reqwest.
///
/// Supports prompt caching and forced tool_use for structured output.
/// Use this as a fallback when LiteLLM proxy is not available.
pub struct AnthropicClient {
    http: reqwest::Client,
    api_url: String,
    api_key: String,
    system_prompt: String,
    enable_cache: bool,
}

impl AnthropicClient {
    const API_URL: &'static str = "https://api.anthropic.com/v1/messages";
    const API_VERSION: &'static str = "2023-06-01";
    const CACHE_BETA: &'static str = "prompt-caching-2024-07-31";
    const MAX_TOKENS: u32 = 4000;

    /// Create a new client. Reads `ANTHROPIC_API_KEY` from environment.
    pub fn from_env(system_prompt: String) -> Result<Self, AiError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY").map_err(|_| AiError::MissingApiKey)?;

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| AiError::Http(e.to_string()))?;

        Ok(Self {
            http,
            api_url: Self::API_URL.to_string(),
            api_key,
            system_prompt,
            enable_cache: true,
        })
    }

    /// Create with explicit API key (for testing).
    pub fn new(api_key: String, system_prompt: String) -> Result<Self, AiError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| AiError::Http(e.to_string()))?;

        Ok(Self {
            http,
            api_url: Self::API_URL.to_string(),
            api_key,
            system_prompt,
            enable_cache: true,
        })
    }

    /// Override the API URL (for testing with mock servers).
    pub fn with_api_url(self, url: String) -> Self {
        Self {
            api_url: url,
            ..self
        }
    }

    /// Disable prompt caching (for testing/comparison).
    pub fn without_cache(self) -> Self {
        Self {
            enable_cache: false,
            ..self
        }
    }

    /// Build the Anthropic-format tool definition.
    fn verdict_tool() -> AnthropicToolDef {
        AnthropicToolDef {
            name: "analyze_evm_trace".to_string(),
            description:
                "Analyze an EVM transaction trace and return a structured security verdict"
                    .to_string(),
            input_schema: verdict_tool_schema(),
        }
    }
}

impl AiClient for AnthropicClient {
    async fn judge(&self, context: &AgentContext, model: &str) -> Result<AiResponse, AiError> {
        let context_json = serialize_context_checked(context)?;

        let cache_control = if self.enable_cache {
            Some(CacheControl {
                type_: "ephemeral".to_string(),
            })
        } else {
            None
        };

        let request_body = AnthropicRequest {
            model: model.to_string(),
            max_tokens: Self::MAX_TOKENS,
            system: vec![SystemBlock {
                type_: "text".to_string(),
                text: self.system_prompt.clone(),
                cache_control,
            }],
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: format!("Analyze this EVM transaction trace:\n\n{context_json}"),
            }],
            tools: vec![Self::verdict_tool()],
            tool_choice: AnthropicToolChoice {
                type_: "tool".to_string(),
                name: "analyze_evm_trace".to_string(),
            },
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-api-key",
            self.api_key.parse().map_err(|_| AiError::MissingApiKey)?,
        );
        headers.insert(
            "anthropic-version",
            Self::API_VERSION
                .parse()
                .map_err(|_| AiError::Http("invalid header".to_string()))?,
        );
        if self.enable_cache {
            headers.insert(
                "anthropic-beta",
                Self::CACHE_BETA
                    .parse()
                    .map_err(|_| AiError::Http("invalid header".to_string()))?,
            );
        }

        let start = Instant::now();

        let response = self
            .http
            .post(&self.api_url)
            .headers(headers)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AiError::Http(e.to_string()))?;

        let status = response.status().as_u16();
        if status >= 400 {
            let body = response.text().await.unwrap_or_default();
            let message = serde_json::from_str::<AnthropicErrorResponse>(&body)
                .ok()
                .and_then(|r| r.error)
                .map(|e| e.message)
                .unwrap_or(body);
            return Err(AiError::Api { status, message });
        }

        let latency_ms = start.elapsed().as_millis() as u64;

        let resp: AnthropicResponse = response
            .json()
            .await
            .map_err(|e| AiError::ParseError(e.to_string()))?;

        let usage = TokenUsage {
            input_tokens: resp.usage.input_tokens,
            output_tokens: resp.usage.output_tokens,
            cache_creation_input_tokens: resp.usage.cache_creation_input_tokens.unwrap_or(0),
            cache_read_input_tokens: resp.usage.cache_read_input_tokens.unwrap_or(0),
        };

        let total_tokens = usage.input_tokens + usage.output_tokens;

        // Find tool_use block
        let tool_input = resp
            .content
            .iter()
            .find_map(|block| match block {
                AnthropicContentBlock::ToolUse { input, .. } => Some(input),
                _ => None,
            })
            .ok_or(AiError::NoToolResponse)?;

        let verdict = parse_verdict(tool_input, model, total_tokens, latency_ms)?;

        Ok(AiResponse { verdict, usage })
    }
}
