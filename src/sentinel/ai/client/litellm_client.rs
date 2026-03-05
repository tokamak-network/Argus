//! LiteLLM proxy client using OpenAI-compatible chat completions API.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;

use super::super::types::AgentContext;
use super::{AiClient, AiError, AiResponse, TokenUsage, parse_verdict, verdict_tool_schema};

// ── OpenAI-compatible API types (request) ────────────────────────────────

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<ChatMessage>,
    tools: Vec<OpenAiToolDef>,
    tool_choice: OpenAiToolChoice,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct OpenAiToolDef {
    #[serde(rename = "type")]
    type_: String,
    function: OpenAiFunctionDef,
}

#[derive(Serialize)]
struct OpenAiFunctionDef {
    name: String,
    description: String,
    parameters: Value,
}

#[derive(Serialize)]
struct OpenAiToolChoice {
    #[serde(rename = "type")]
    type_: String,
    function: OpenAiToolChoiceName,
}

#[derive(Serialize)]
struct OpenAiToolChoiceName {
    name: String,
}

// ── OpenAI-compatible API types (response) ───────────────────────────────

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
    usage: ChatUsageResponse,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    #[serde(default)]
    tool_calls: Option<Vec<ChatToolCall>>,
}

#[derive(Deserialize)]
struct ChatToolCall {
    function: ChatFunctionCall,
}

#[derive(Deserialize)]
struct ChatFunctionCall {
    #[allow(dead_code)]
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ChatUsageResponse {
    prompt_tokens: u32,
    completion_tokens: u32,
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
}

#[derive(Deserialize)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: Option<u32>,
}

#[derive(Deserialize)]
struct OpenAiErrorResponse {
    error: Option<OpenAiErrorDetail>,
}

#[derive(Deserialize)]
struct OpenAiErrorDetail {
    message: String,
}

// ── LiteLLMClient ────────────────────────────────────────────────────────

/// LiteLLM proxy client using OpenAI-compatible chat completions API.
///
/// Prompt caching is handled transparently by LiteLLM when routing
/// to Anthropic backends.
pub struct LiteLLMClient {
    http: reqwest::Client,
    api_base: String,
    api_key: String,
    system_prompt: String,
}

impl LiteLLMClient {
    pub(crate) const DEFAULT_API_BASE: &'static str = "https://api.ai.tokamak.network";
    const MAX_TOKENS: u32 = 4000;

    /// Create from environment variables.
    ///
    /// - `LITELLM_BASE_URL` — proxy URL (default: `https://api.ai.tokamak.network`)
    /// - `LITELLM_API_KEY` — proxy API key
    pub fn from_env(system_prompt: String) -> Result<Self, AiError> {
        let api_key = std::env::var("LITELLM_API_KEY").map_err(|_| AiError::MissingApiKey)?;
        let api_base = std::env::var("LITELLM_BASE_URL")
            .unwrap_or_else(|_| Self::DEFAULT_API_BASE.to_string());

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| AiError::Http(e.to_string()))?;

        Ok(Self {
            http,
            api_base,
            api_key,
            system_prompt,
        })
    }

    /// Create with explicit configuration (for testing).
    pub fn new(api_base: String, api_key: String, system_prompt: String) -> Result<Self, AiError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| AiError::Http(e.to_string()))?;

        Ok(Self {
            http,
            api_base,
            api_key,
            system_prompt,
        })
    }

    /// Build the OpenAI-format tool definition.
    fn verdict_tool() -> OpenAiToolDef {
        OpenAiToolDef {
            type_: "function".to_string(),
            function: OpenAiFunctionDef {
                name: "analyze_evm_trace".to_string(),
                description:
                    "Analyze an EVM transaction trace and return a structured security verdict"
                        .to_string(),
                parameters: verdict_tool_schema(),
            },
        }
    }
}

impl AiClient for LiteLLMClient {
    // TODO(phase1-pre-prod): Add mock HTTP tests (wiremock/mockito) for this method before production.
    //   Required scenarios: 200 OK with valid tool_call, 429 rate limit, empty choices,
    //   malformed JSON body, network timeout. See devil review 2nd round — 종목 7 감점.
    // TODO(phase1-pre-prod): Guard AgentContext size before serialization.
    //   Use context.approx_json_bytes() and reject if > MAX_CONTEXT_BYTES to prevent
    //   unbounded API spend from adversarial TX traces. See devil review 2nd round — 종목 2 감점.
    async fn judge(&self, context: &AgentContext, model: &str) -> Result<AiResponse, AiError> {
        let context_json =
            serde_json::to_string(context).map_err(|e| AiError::ParseError(e.to_string()))?;

        let request_body = ChatCompletionRequest {
            model: model.to_string(),
            max_tokens: Self::MAX_TOKENS,
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: self.system_prompt.clone(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: format!("Analyze this EVM transaction trace:\n\n{context_json}"),
                },
            ],
            tools: vec![Self::verdict_tool()],
            tool_choice: OpenAiToolChoice {
                type_: "function".to_string(),
                function: OpenAiToolChoiceName {
                    name: "analyze_evm_trace".to_string(),
                },
            },
        };

        let url = format!(
            "{}/v1/chat/completions",
            self.api_base.trim_end_matches('/')
        );

        let start = Instant::now();

        let response = self
            .http
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AiError::Http(e.to_string()))?;

        let status = response.status().as_u16();
        if status >= 400 {
            let body = response.text().await.unwrap_or_default();
            let message = serde_json::from_str::<OpenAiErrorResponse>(&body)
                .ok()
                .and_then(|r| r.error)
                .map(|e| e.message)
                .unwrap_or(body);
            return Err(AiError::Api { status, message });
        }

        let latency_ms = start.elapsed().as_millis() as u64;

        let resp: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| AiError::ParseError(e.to_string()))?;

        let cached_tokens = resp
            .usage
            .prompt_tokens_details
            .as_ref()
            .and_then(|d| d.cached_tokens)
            .unwrap_or(0);

        let usage = TokenUsage {
            input_tokens: resp.usage.prompt_tokens,
            output_tokens: resp.usage.completion_tokens,
            cache_creation_input_tokens: 0, // LiteLLM doesn't expose cache write separately
            cache_read_input_tokens: cached_tokens,
        };

        let total_tokens = usage.input_tokens + usage.output_tokens;

        // Extract tool call arguments from first choice
        let tool_calls = resp
            .choices
            .first()
            .and_then(|c| c.message.tool_calls.as_ref())
            .ok_or(AiError::NoToolResponse)?;

        let arguments_str = &tool_calls
            .first()
            .ok_or(AiError::NoToolResponse)?
            .function
            .arguments;

        let tool_input: Value =
            serde_json::from_str(arguments_str).map_err(|e| AiError::ParseError(e.to_string()))?;

        let verdict = parse_verdict(&tool_input, model, total_tokens, latency_ms)?;

        Ok(AiResponse { verdict, usage })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn litellm_verdict_tool_has_openai_format() {
        let tool = LiteLLMClient::verdict_tool();
        assert_eq!(tool.type_, "function");
        assert_eq!(tool.function.name, "analyze_evm_trace");
        assert!(tool.function.parameters.get("properties").is_some());
    }

    #[test]
    fn litellm_default_api_base() {
        assert_eq!(
            LiteLLMClient::DEFAULT_API_BASE,
            "https://api.ai.tokamak.network"
        );
    }
}
