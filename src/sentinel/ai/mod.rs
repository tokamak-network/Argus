//! AI Agent integration module.
//!
//! This module is only compiled when the `ai_agent` feature is enabled.
//! It provides types and infrastructure for LLM-based TX analysis.
//!
//! # Architecture
//!
//! ```text
//! CostTracker.can_afford() → AiClient.judge(AgentContext) → AgentVerdict → CostTracker.record()
//! ```
//!
//! Files in this module:
//! - `types.rs`           — AgentContext, AgentVerdict, AttackType, sub-types, CostTracker
//! - `context.rs`         — ContextExtractor (trace → AgentContext)
//! - `judge.rs`           — AiJudge (2-tier screening/deep pipeline)
//! - `guard.rs`           — Hallucination Guard (evidence verification)
//! - `client.rs`          — AiClient trait + LiteLLMClient + AnthropicClient
//! - `cost.rs`            — CostTracker persistence + date helpers
//! - `ai_config.rs`       — AiConfig TOML configuration
//! - `rate_limit.rs`      — HourlyRateTracker + BlockConcurrencyTracker
//! - `circuit_breaker.rs` — CircuitBreaker for API failure protection
//! - `prompts.rs`         — System/user prompt templates

pub mod ai_config;
pub mod circuit_breaker;
pub mod client;
pub mod context;
#[cfg(test)]
mod context_test;
pub mod cost;
#[cfg(test)]
mod cost_test;
pub mod fixtures;
pub mod guard;
#[cfg(test)]
mod guard_test;
pub mod judge;
#[cfg(test)]
mod judge_test;
#[cfg(test)]
mod client_http_test;
#[cfg(test)]
mod poc_test;
pub mod prompts;
pub mod rate_limit;
pub mod types;

pub use ai_config::AiConfig;
pub use circuit_breaker::CircuitBreaker;
pub use client::{AiClient, AiError, AiResponse, AnthropicClient, LiteLLMClient, TokenUsage};
pub use context::{ContextExtractor, ExtractParams};
pub use guard::validate_evidence;
pub use judge::JudgeError;
pub use prompts::SYSTEM_PROMPT;
pub use rate_limit::{BlockConcurrencyTracker, HourlyRateTracker};
pub use types::{
    AgentContext, AgentVerdict, AttackType, CallFrame, CallType, ContractCreation, CostTracker,
    CreateType, DelegateCallInfo, EthTransfer, LogEvent, StorageMutation, TokenTransfer,
};
