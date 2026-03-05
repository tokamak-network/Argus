//! Shared test helpers for Phase 1 integration tests (T5).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::sentinel::ai::client::{AiClient, AiError, AiResponse, TokenUsage};
use crate::sentinel::ai::context::{ContextExtractor, ExtractParams};
use crate::sentinel::ai::types::{AgentContext, AgentVerdict};
use crate::types::StepRecord;
use ethrex_common::{Address, H256, U256};

// ── Opcode constants ─────────────────────────────────────────────────────

pub const OP_CALL: u8 = 0xF1;
pub const OP_CALLCODE: u8 = 0xF2;
pub const OP_DELEGATECALL: u8 = 0xF4;
pub const OP_STATICCALL: u8 = 0xFA;
pub const OP_ADD: u8 = 0x01;

// ── Basic helpers ────────────────────────────────────────────────────────

pub fn addr(byte: u8) -> Address {
    Address::from([byte; 20])
}

pub fn h256(byte: u8) -> H256 {
    H256::from([byte; 32])
}

pub fn u256_addr(a: Address) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(a.as_bytes());
    U256::from_big_endian(&bytes)
}

pub fn make_step(opcode: u8, depth: usize, code_addr: Address) -> StepRecord {
    StepRecord {
        step_index: 0,
        pc: 0,
        opcode,
        depth,
        gas_remaining: 100_000,
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address: code_addr,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

pub fn extract(steps: &[StepRecord]) -> AgentContext {
    ContextExtractor::extract(
        steps,
        ExtractParams {
            tx_hash: h256(0x01),
            block_number: 21_000_000,
            from: addr(0xAA),
            to: Some(addr(0xBB)),
            value_wei: U256::zero(),
            gas_used: 100_000,
            succeeded: true,
            suspicious_score: 0.5,
            suspicion_reasons: vec!["test".to_string()],
        },
    )
}

pub fn minimal_context() -> AgentContext {
    AgentContext {
        tx_hash: h256(1),
        block_number: 21_000_000,
        from: addr(0xAA),
        to: Some(addr(0xBB)),
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

pub fn benign_verdict() -> AgentVerdict {
    AgentVerdict {
        is_attack: false,
        confidence: 0.1,
        attack_type: None,
        reasoning: "Normal transaction".to_string(),
        evidence: vec!["Low gas usage".to_string()],
        evidence_valid: false,
        false_positive_reason: Some("Standard swap".to_string()),
        model_used: "gemini-3-flash".to_string(),
        tokens_used: 500,
        latency_ms: 300,
    }
}

pub fn mock_usage() -> TokenUsage {
    TokenUsage {
        input_tokens: 1000,
        output_tokens: 500,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    }
}

// ── Unique temp paths ────────────────────────────────────────────────────

static PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn unique_path() -> PathBuf {
    let id = PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/tmp/argus_t5_test_{}_{}.json",
        std::process::id(),
        id,
    ))
}

pub fn cleanup(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

// ── Mock AI Client ───────────────────────────────────────────────────────

pub struct TrackingMockClient {
    pub verdict: AgentVerdict,
    pub call_count: AtomicU64,
}

impl TrackingMockClient {
    pub fn new(verdict: AgentVerdict) -> Self {
        Self {
            verdict,
            call_count: AtomicU64::new(0),
        }
    }
}

impl AiClient for TrackingMockClient {
    async fn judge(&self, _context: &AgentContext, _model: &str) -> Result<AiResponse, AiError> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        Ok(AiResponse {
            verdict: self.verdict.clone(),
            usage: mock_usage(),
        })
    }
}
