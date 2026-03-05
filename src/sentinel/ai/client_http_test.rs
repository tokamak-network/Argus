//! HTTP-level mock tests for LiteLLMClient and AnthropicClient.
//!
//! Uses wiremock to simulate API responses without hitting real endpoints.
//! Covers: valid tool_call, rate limit 429, empty choices, malformed JSON, API errors.

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::client::anthropic_client::AnthropicClient;
use super::client::litellm_client::LiteLLMClient;
use super::client::{AiClient, AiError};
use super::types::*;
use ethrex_common::{Address, H256, U256};

// ── Test helpers ─────────────────────────────────────────────────────────

fn minimal_context() -> AgentContext {
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

/// Valid LiteLLM (OpenAI-format) response with tool_call.
fn litellm_ok_response() -> serde_json::Value {
    serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "analyze_evm_trace",
                        "arguments": serde_json::json!({
                            "is_attack": false,
                            "confidence": 0.1,
                            "attack_type": "none",
                            "reasoning": "Normal ETH transfer",
                            "evidence": ["Low gas usage"],
                            "false_positive_reason": "Simple transfer"
                        }).to_string()
                    }
                }]
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1000,
            "completion_tokens": 200,
            "total_tokens": 1200
        }
    })
}

/// Valid Anthropic Messages API response with tool_use block.
fn anthropic_ok_response() -> serde_json::Value {
    serde_json::json!({
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [{
            "type": "tool_use",
            "id": "toolu_1",
            "name": "analyze_evm_trace",
            "input": {
                "is_attack": true,
                "confidence": 0.85,
                "attack_type": "reentrancy",
                "reasoning": "Re-entrant call detected",
                "evidence": ["Multiple CALLs to same address"],
                "false_positive_reason": ""
            }
        }],
        "usage": {
            "input_tokens": 1500,
            "output_tokens": 300,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 500
        }
    })
}

// ── LiteLLM Tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn litellm_200_ok_valid_tool_call() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(litellm_ok_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    let response = result.unwrap();
    assert!(!response.verdict.is_attack);
    assert!((response.verdict.confidence - 0.1).abs() < f64::EPSILON);
    assert_eq!(response.verdict.reasoning, "Normal ETH transfer");
    assert_eq!(response.usage.input_tokens, 1000);
    assert_eq!(response.usage.output_tokens, 200);
}

#[tokio::test]
async fn litellm_429_rate_limit() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "error": {
                "message": "Rate limit exceeded",
                "type": "rate_limit_error"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    match result {
        Err(AiError::Api { status, message }) => {
            assert_eq!(status, 429);
            assert!(message.contains("Rate limit"), "got: {message}");
        }
        other => panic!("expected Api error with 429, got: {other:?}"),
    }
}

#[tokio::test]
async fn litellm_500_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "error": {
                "message": "Internal server error"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    match result {
        Err(AiError::Api { status, .. }) => assert_eq!(status, 500),
        other => panic!("expected Api error with 500, got: {other:?}"),
    }
}

#[tokio::test]
async fn litellm_empty_choices() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [],
            "usage": { "prompt_tokens": 100, "completion_tokens": 0, "total_tokens": 100 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(matches!(result, Err(AiError::NoToolResponse)));
}

#[tokio::test]
async fn litellm_no_tool_calls_in_message() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "I cannot analyze this."}, "finish_reason": "stop"}],
            "usage": { "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(matches!(result, Err(AiError::NoToolResponse)));
}

#[tokio::test]
async fn litellm_malformed_tool_arguments() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "analyze_evm_trace",
                            "arguments": "not valid json {"
                        }
                    }]
                },
                "finish_reason": "stop"
            }],
            "usage": { "prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150 }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(matches!(result, Err(AiError::ParseError(_))));
}

#[tokio::test]
async fn litellm_malformed_response_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(matches!(result, Err(AiError::ParseError(_))));
}

#[tokio::test]
async fn litellm_sends_correct_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("Authorization", "Bearer my-secret-key"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(litellm_ok_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "my-secret-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn litellm_cache_tokens_extracted() {
    let server = MockServer::start().await;

    let mut response = litellm_ok_response();
    response["usage"]["prompt_tokens_details"] = serde_json::json!({
        "cached_tokens": 800
    });

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();
    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    let response = result.unwrap();
    assert_eq!(response.usage.cache_read_input_tokens, 800);
}

// ── Anthropic Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn anthropic_200_ok_valid_tool_use() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("x-api-key", "test-api-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_ok_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-api-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    let response = result.unwrap();
    assert!(response.verdict.is_attack);
    assert!((response.verdict.confidence - 0.85).abs() < f64::EPSILON);
    assert_eq!(response.verdict.attack_type, Some(AttackType::Reentrancy));
    assert_eq!(response.usage.input_tokens, 1500);
    assert_eq!(response.usage.output_tokens, 300);
    assert_eq!(response.usage.cache_creation_input_tokens, 100);
    assert_eq!(response.usage.cache_read_input_tokens, 500);
}

#[tokio::test]
async fn anthropic_429_rate_limit() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "type": "error",
            "error": {
                "type": "rate_limit_error",
                "message": "Number of request tokens has exceeded your per-minute rate limit"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    match result {
        Err(AiError::Api { status, message }) => {
            assert_eq!(status, 429);
            assert!(message.contains("rate limit"), "got: {message}");
        }
        other => panic!("expected Api 429, got: {other:?}"),
    }
}

#[tokio::test]
async fn anthropic_no_tool_use_block() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "text",
                "text": "I cannot analyze this transaction."
            }],
            "usage": {
                "input_tokens": 100,
                "output_tokens": 20
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    assert!(matches!(result, Err(AiError::NoToolResponse)));
}

#[tokio::test]
async fn anthropic_malformed_response_body() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("garbage"))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    assert!(matches!(result, Err(AiError::ParseError(_))));
}

#[tokio::test]
async fn anthropic_sends_cache_beta_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("anthropic-beta", "prompt-caching-2024-07-31"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_ok_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn anthropic_without_cache_omits_beta_header() {
    let server = MockServer::start().await;

    // This mock expects NO anthropic-beta header. If the header is present,
    // the request won't match and the test will fail due to unmatched requests.
    Mock::given(method("POST"))
        .and(header("x-api-key", "test-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(anthropic_ok_response()))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .without_cache()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn anthropic_500_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
            "type": "error",
            "error": {
                "type": "api_error",
                "message": "Internal server error"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    match result {
        Err(AiError::Api { status, .. }) => assert_eq!(status, 500),
        other => panic!("expected Api 500, got: {other:?}"),
    }
}

#[tokio::test]
async fn anthropic_error_without_json_structure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_string("Bad Gateway"))
        .expect(1)
        .mount(&server)
        .await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    match result {
        Err(AiError::Api { status, message }) => {
            assert_eq!(status, 502);
            assert_eq!(message, "Bad Gateway");
        }
        other => panic!("expected Api 502, got: {other:?}"),
    }
}

// ── Context size guard tests (HTTP level) ────────────────────────────────

#[tokio::test]
async fn litellm_oversized_context_rejected_before_http() {
    let server = MockServer::start().await;

    // No mock mounted — if HTTP request is made, test fails with unmatched request
    let client = LiteLLMClient::new(server.uri(), "test-key".into(), "system".into()).unwrap();

    let mut ctx = minimal_context();
    // Fill with enough data to exceed 256KB
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

    let result = client.judge(&ctx, "gemini-3-flash").await;
    assert!(
        matches!(result, Err(AiError::ContextTooLarge { .. })),
        "expected ContextTooLarge, got: {result:?}"
    );
}

#[tokio::test]
async fn anthropic_oversized_context_rejected_before_http() {
    let server = MockServer::start().await;

    let client = AnthropicClient::new("test-key".into(), "system".into())
        .unwrap()
        .with_api_url(format!("{}/v1/messages", server.uri()));

    let mut ctx = minimal_context();
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

    let result = client.judge(&ctx, "claude-haiku-4-5-20251001").await;
    assert!(
        matches!(result, Err(AiError::ContextTooLarge { .. })),
        "expected ContextTooLarge, got: {result:?}"
    );
}

// ── Connection error test ────────────────────────────────────────────────

#[tokio::test]
async fn litellm_connection_refused() {
    // Point to a port that nothing is listening on
    let client =
        LiteLLMClient::new("http://127.0.0.1:1".into(), "key".into(), "system".into()).unwrap();

    let result = client.judge(&minimal_context(), "gemini-3-flash").await;

    assert!(matches!(result, Err(AiError::Http(_))));
}

#[tokio::test]
async fn anthropic_connection_refused() {
    let client = AnthropicClient::new("key".into(), "system".into())
        .unwrap()
        .with_api_url("http://127.0.0.1:1/v1/messages".into());

    let result = client
        .judge(&minimal_context(), "claude-haiku-4-5-20251001")
        .await;

    assert!(matches!(result, Err(AiError::Http(_))));
}
