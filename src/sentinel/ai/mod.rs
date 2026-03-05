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
//! - `types.rs`   — AgentContext, AgentVerdict, AttackType, sub-types, CostTracker
//! - `context.rs` — ContextExtractor (trace → AgentContext) [TODO: Phase 1]
//! - `judge.rs`   — AiJudge (2-tier Haiku/Sonnet pipeline) [TODO: Phase 1]
//! - `guard.rs`   — Hallucination Guard (evidence verification) [TODO: Phase 1]
//! - `client.rs`  — AiClient trait + LiteLLMClient (primary) + AnthropicClient (fallback)
//! - `cost.rs`    — CostTracker persistence + circuit breaker [TODO: Phase 1]
//! - `prompts.rs` — System/user prompt templates

pub mod client;
pub mod fixtures;
#[cfg(test)]
mod poc_test;
pub mod prompts;
pub mod types;

pub use client::{AiClient, AiError, AiResponse, AnthropicClient, LiteLLMClient, TokenUsage};
pub use prompts::SYSTEM_PROMPT;
pub use types::{
    AgentContext, AgentVerdict, AttackType, CallFrame, CallType, ContractCreation, CostTracker,
    CreateType, DelegateCallInfo, EthTransfer, LogEvent, StorageMutation, TokenTransfer,
};
