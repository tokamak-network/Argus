//! AI Agent type definitions: AgentContext, AgentVerdict, AttackType, and sub-types.
//!
//! All types are JSON-serializable via serde. Address/H256/U256 use ethrex_common types.

use ethrex_common::{Address, H256, U256};
use serde::{Deserialize, Serialize};

// ── AttackType ──────────────────────────────────────────────────────────────

/// Attack classification returned by the AI agent.
///
/// LLM output is mapped to this enum. Unmapped strings fall back to `Other(raw)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
pub enum AttackType {
    Reentrancy,
    FlashLoan,
    PriceManipulation,
    AccessControl,
    FrontRunning,
    Sandwich,
    /// Catch-all for attack types not yet classified.
    Other(String),
}

impl AttackType {
    /// Parse a raw string (LLM output) into an AttackType.
    /// Matching is case-insensitive. Unknown strings become `Other(s)`.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "reentrancy" => Self::Reentrancy,
            "flashloan" | "flash_loan" | "flash loan" => Self::FlashLoan,
            "pricemanipulation" | "price_manipulation" | "price manipulation" => {
                Self::PriceManipulation
            }
            "accesscontrol" | "access_control" | "access control" => Self::AccessControl,
            "frontrunning" | "front_running" | "front running" => Self::FrontRunning,
            "sandwich" => Self::Sandwich,
            other => Self::Other(other.to_string()),
        }
    }
}

// ── CallType / CreateType ────────────────────────────────────────────────────

/// EVM call instruction variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallType {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
}

/// EVM contract creation instruction variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateType {
    Create,
    Create2,
}

// ── Sub-types ────────────────────────────────────────────────────────────────

/// A single frame in the EVM call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallFrame {
    /// EVM call depth (0-based). Max EVM depth is 1024, so u16 is sufficient.
    pub depth: u16,
    pub caller: Address,
    pub target: Address,
    pub value: U256,
    /// First 4 bytes of calldata (function selector). None for raw ETH sends.
    pub input_selector: Option<[u8; 4]>,
    pub input_size: usize,
    pub output_size: usize,
    pub gas_used: u64,
    pub call_type: CallType,
    pub reverted: bool,
}

/// A storage slot mutation observed during TX execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMutation {
    pub contract: Address,
    pub slot: H256,
    pub old_value: H256,
    pub new_value: H256,
    /// True if this mutation occurred inside a callback (reentrancy indicator).
    pub in_callback: bool,
}

/// An ERC-20 Transfer event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransfer {
    pub token: Address,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
}

/// An ETH value transfer (CALL with non-zero value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthTransfer {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    /// Call depth at which the transfer occurred.
    pub call_depth: u16,
}

/// A non-Transfer log event (Approval, Swap, Sync, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub address: Address,
    /// event signature hash (topic[0]).
    pub topic0: H256,
    /// Indexed parameters (topic[1..]).
    pub topics: Vec<H256>,
    /// Byte length of non-indexed (data) field.
    pub data_size: usize,
}

/// A DELEGATECALL observed during TX execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateCallInfo {
    pub caller: Address,
    pub target: Address,
    /// None for proxy fallback / empty calldata patterns.
    pub input_selector: Option<[u8; 4]>,
}

/// A contract deployed during TX execution (CREATE / CREATE2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCreation {
    pub deployer: Address,
    pub deployed: Address,
    pub code_size: usize,
    pub create_type: CreateType,
}

// ── AgentContext ─────────────────────────────────────────────────────────────

/// Full TX analysis context passed to the AI agent.
///
/// Extracted from opcode-level trace. Serialised to JSON (~2-5 KB) and sent
/// as the user message in the Claude API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContext {
    pub tx_hash: H256,
    pub block_number: u64,
    pub from: Address,
    /// `None` for contract-creation transactions.
    pub to: Option<Address>,
    pub value_wei: U256,
    pub gas_used: u64,
    pub succeeded: bool,
    /// Number of internal reverts (key reentrancy signal).
    pub revert_count: u32,
    /// Pre-filter suspicion score (0.0 – 1.0).
    pub suspicious_score: f64,
    /// Human-readable reasons from the pre-filter.
    pub suspicion_reasons: Vec<String>,
    pub call_graph: Vec<CallFrame>,
    pub storage_mutations: Vec<StorageMutation>,
    pub erc20_transfers: Vec<TokenTransfer>,
    pub eth_transfers: Vec<EthTransfer>,
    pub log_events: Vec<LogEvent>,
    pub delegatecalls: Vec<DelegateCallInfo>,
    pub contract_creations: Vec<ContractCreation>,
}

impl AgentContext {
    /// Approximate serialised byte size (for context-size budget checks).
    ///
    /// Uses `serde_json` serialisation. Returns `Err` if serialisation fails.
    pub fn approx_json_bytes(&self) -> Result<usize, serde_json::Error> {
        Ok(serde_json::to_string(self)?.len())
    }
}

// ── AgentVerdict ─────────────────────────────────────────────────────────────

/// AI judgement result for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVerdict {
    pub is_attack: bool,
    /// Confidence 0.0 – 1.0.
    pub confidence: f64,
    pub attack_type: Option<AttackType>,
    /// Natural-language reasoning from the model.
    pub reasoning: String,
    /// Key evidence items cited by the model.
    pub evidence: Vec<String>,
    /// Hallucination Guard result: true if all evidence items verified against context.
    pub evidence_valid: bool,
    /// Why the model thinks this is a false positive (if applicable).
    pub false_positive_reason: Option<String>,
    /// Model identifier used (e.g. "claude-haiku-4-5-20251001").
    pub model_used: String,
    pub tokens_used: u32,
    pub latency_ms: u64,
}

// ── CostTracker ──────────────────────────────────────────────────────────────

/// Tracks API cost and enforces monthly/daily budget limits.
///
/// Persisted as JSON. Use [`CostTracker::can_afford`] before every API call.
///
/// Note on f64 precision: at $150/month scale with 30,000 requests, accumulated
/// floating-point error is < $0.001. Comparisons use an epsilon of `0.01`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTracker {
    /// Monthly spend ceiling in USD (default 150.0).
    pub monthly_budget_usd: f64,
    /// Daily spend ceiling in USD (default 10.0).
    pub daily_limit_usd: f64,
    /// Maximum AI requests per hour. Enforced by HourlyRateTracker in AiJudge.
    pub hourly_rate_limit: u32,
    /// Maximum concurrent AI requests per block. Enforced by BlockConcurrencyTracker in AiJudge.
    pub max_concurrent_per_block: u8,

    // Running totals (reset periodically)
    pub total_cost_usd: f64,
    pub today_cost_usd: f64,
    pub total_tokens: u64,
    pub request_count: u32,
    pub haiku_requests: u32,
    pub sonnet_requests: u32,

    /// ISO-8601 date string of the last daily reset.
    pub last_daily_reset: String,
    /// ISO-8601 date string of the last monthly reset.
    pub last_monthly_reset: String,
    /// True when the monthly budget has been exhausted.
    pub budget_exhausted: bool,
}

impl CostTracker {
    /// Returns true if a request costing `estimated_usd` can proceed.
    ///
    /// Checks monthly budget, daily limit, and exhaustion flag.
    /// Does NOT mutate state — call [`CostTracker::record`] after a successful call.
    ///
    /// Note: hourly_rate_limit and max_concurrent_per_block are enforced by
    /// AiJudge (HourlyRateTracker + BlockConcurrencyTracker), not in this method.
    pub fn can_afford(&self, estimated_usd: f64) -> bool {
        const EPSILON: f64 = 0.01;
        if self.budget_exhausted {
            return false;
        }
        let monthly_ok = self.total_cost_usd + estimated_usd <= self.monthly_budget_usd + EPSILON;
        let daily_ok = self.today_cost_usd + estimated_usd <= self.daily_limit_usd + EPSILON;
        monthly_ok && daily_ok
    }

    /// Record a completed API call's cost and token usage.
    pub fn record(&mut self, cost_usd: f64, tokens: u32, model: &str) {
        self.total_cost_usd += cost_usd;
        self.today_cost_usd += cost_usd;
        self.total_tokens += u64::from(tokens);
        self.request_count += 1;

        if model.contains("haiku") {
            self.haiku_requests += 1;
        } else if model.contains("sonnet") {
            self.sonnet_requests += 1;
        }

        const EPSILON: f64 = 0.01;
        if self.total_cost_usd >= self.monthly_budget_usd - EPSILON {
            self.budget_exhausted = true;
        }
    }
}

impl Default for CostTracker {
    fn default() -> Self {
        Self {
            monthly_budget_usd: 150.0,
            daily_limit_usd: 10.0,
            hourly_rate_limit: 100,
            max_concurrent_per_block: 3,
            total_cost_usd: 0.0,
            today_cost_usd: 0.0,
            total_tokens: 0,
            request_count: 0,
            haiku_requests: 0,
            sonnet_requests: 0,
            last_daily_reset: String::new(),
            last_monthly_reset: String::new(),
            budget_exhausted: false,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{Address, H256, U256};

    // Helper: zero address
    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    // ── AttackType tests ─────────────────────────────────────────────────────

    #[test]
    fn attack_type_known_variants_roundtrip() {
        let cases = [
            ("reentrancy", AttackType::Reentrancy),
            ("flashloan", AttackType::FlashLoan),
            ("flash_loan", AttackType::FlashLoan),
            ("flash loan", AttackType::FlashLoan),
            ("pricemanipulation", AttackType::PriceManipulation),
            ("price_manipulation", AttackType::PriceManipulation),
            ("accesscontrol", AttackType::AccessControl),
            ("access_control", AttackType::AccessControl),
            ("frontrunning", AttackType::FrontRunning),
            ("front_running", AttackType::FrontRunning),
            ("sandwich", AttackType::Sandwich),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                AttackType::from_str_lossy(input),
                *expected,
                "failed for input: {input}"
            );
        }
    }

    #[test]
    fn attack_type_case_insensitive() {
        assert_eq!(
            AttackType::from_str_lossy("REENTRANCY"),
            AttackType::Reentrancy
        );
        assert_eq!(
            AttackType::from_str_lossy("FlashLoan"),
            AttackType::FlashLoan
        );
    }

    #[test]
    fn attack_type_unknown_becomes_other() {
        let result = AttackType::from_str_lossy("governance takeover");
        assert!(matches!(result, AttackType::Other(_)));
        if let AttackType::Other(s) = result {
            assert_eq!(s, "governance takeover");
        }
    }

    #[test]
    fn attack_type_json_roundtrip() {
        let variants: Vec<AttackType> = vec![
            AttackType::Reentrancy,
            AttackType::FlashLoan,
            AttackType::PriceManipulation,
            AttackType::AccessControl,
            AttackType::FrontRunning,
            AttackType::Sandwich,
            AttackType::Other("custom attack".to_string()),
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: AttackType = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, variant);
        }
    }

    // ── AgentContext tests ───────────────────────────────────────────────────

    fn minimal_context() -> AgentContext {
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

    #[test]
    fn agent_context_json_roundtrip_minimal() {
        let ctx = minimal_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.tx_hash, ctx.tx_hash);
        assert_eq!(decoded.block_number, ctx.block_number);
        assert_eq!(decoded.gas_used, ctx.gas_used);
        assert_eq!(decoded.succeeded, ctx.succeeded);
    }

    #[test]
    fn agent_context_contract_creation_to_is_none() {
        let mut ctx = minimal_context();
        ctx.to = None;
        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert!(decoded.to.is_none());
    }

    #[test]
    fn agent_context_with_call_graph_roundtrip() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![
            CallFrame {
                depth: 0,
                caller: addr(0xAA),
                target: addr(0xBB),
                value: U256::zero(),
                input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
                input_size: 68,
                output_size: 32,
                gas_used: 50_000,
                call_type: CallType::Call,
                reverted: false,
            },
            CallFrame {
                depth: 1,
                caller: addr(0xBB),
                target: addr(0xCC),
                value: U256::from(1_000_000_u64),
                input_selector: None,
                input_size: 0,
                output_size: 0,
                gas_used: 2_300,
                call_type: CallType::Call,
                reverted: true,
            },
        ];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.call_graph.len(), 2);
        assert_eq!(
            decoded.call_graph[0].input_selector,
            Some([0xde, 0xad, 0xbe, 0xef])
        );
        assert!(decoded.call_graph[0].input_selector.is_some());
        assert!(decoded.call_graph[1].input_selector.is_none());
        assert!(decoded.call_graph[1].reverted);
    }

    #[test]
    fn agent_context_with_storage_mutations_roundtrip() {
        let mut ctx = minimal_context();
        ctx.storage_mutations = vec![StorageMutation {
            contract: addr(0xBB),
            slot: h256(0x01),
            old_value: h256(0x00),
            new_value: h256(0x01),
            in_callback: true,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.storage_mutations.len(), 1);
        assert!(decoded.storage_mutations[0].in_callback);
    }

    #[test]
    fn agent_context_with_erc20_transfers_roundtrip() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_000_000_000_000_u64), // 1 ETH in wei
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.erc20_transfers.len(), 1);
        assert_eq!(
            decoded.erc20_transfers[0].amount,
            U256::from(1_000_000_000_000_000_000_u64)
        );
    }

    #[test]
    fn agent_context_approx_json_bytes_is_reasonable() {
        let ctx = minimal_context();
        let size = ctx.approx_json_bytes().unwrap();
        // Minimal context is small but non-trivial
        assert!(size > 100, "expected > 100 bytes, got {size}");
        // Even a minimal context shouldn't be huge
        assert!(size < 2_000, "expected < 2000 bytes, got {size}");
    }

    #[test]
    fn agent_context_full_fields_size_within_5kb() {
        let mut ctx = minimal_context();
        ctx.revert_count = 5;
        ctx.suspicious_score = 0.85;
        ctx.suspicion_reasons = vec![
            "high gas usage".to_string(),
            "multiple internal reverts".to_string(),
            "large value transfer".to_string(),
        ];

        // Add enough call frames to simulate a realistic attack
        for i in 0..10_u8 {
            ctx.call_graph.push(CallFrame {
                depth: u16::from(i % 5),
                caller: addr(i),
                target: addr(i + 1),
                value: U256::zero(),
                input_selector: Some([0xab, 0xcd, 0xef, i]),
                input_size: 132,
                output_size: 32,
                gas_used: 10_000,
                call_type: CallType::Call,
                reverted: i % 3 == 0,
            });
        }

        for i in 0..5_u8 {
            ctx.storage_mutations.push(StorageMutation {
                contract: addr(i + 1),
                slot: h256(i),
                old_value: h256(0),
                new_value: h256(i + 1),
                in_callback: i % 2 == 0,
            });
            ctx.erc20_transfers.push(TokenTransfer {
                token: addr(0x10 + i),
                from: addr(0x20),
                to: addr(0x30),
                amount: U256::from(u64::from(i + 1) * 1_000_000_000_u64),
            });
        }

        let size = ctx.approx_json_bytes().unwrap();
        // PRD specifies ~2-5KB; test data uses hex-encoded H256/Address which inflate size.
        // 6KB ceiling covers realistic attack context (10 call frames + 5 mutations + 5 transfers).
        assert!(
            size <= 6_144,
            "context size {size} bytes exceeds 6KB ceiling"
        );
    }

    #[test]
    fn agent_context_with_log_events_roundtrip() {
        let mut ctx = minimal_context();
        ctx.log_events = vec![LogEvent {
            address: addr(0x55),
            topic0: h256(0xAA),
            topics: vec![h256(0xBB), h256(0xCC)],
            data_size: 64,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.log_events.len(), 1);
        assert_eq!(decoded.log_events[0].topics.len(), 2);
        assert_eq!(decoded.log_events[0].data_size, 64);
    }

    #[test]
    fn agent_context_with_delegatecalls_roundtrip() {
        let mut ctx = minimal_context();
        ctx.delegatecalls = vec![
            DelegateCallInfo {
                caller: addr(0x01),
                target: addr(0x02),
                input_selector: Some([0x12, 0x34, 0x56, 0x78]),
            },
            DelegateCallInfo {
                caller: addr(0x03),
                target: addr(0x04),
                input_selector: None, // proxy fallback
            },
        ];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.delegatecalls.len(), 2);
        assert!(decoded.delegatecalls[0].input_selector.is_some());
        assert!(decoded.delegatecalls[1].input_selector.is_none());
    }

    #[test]
    fn agent_context_with_contract_creations_roundtrip() {
        let mut ctx = minimal_context();
        ctx.contract_creations = vec![ContractCreation {
            deployer: addr(0x01),
            deployed: addr(0x02),
            code_size: 1024,
            create_type: CreateType::Create2,
        }];

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: AgentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.contract_creations.len(), 1);
        assert_eq!(
            decoded.contract_creations[0].create_type,
            CreateType::Create2
        );
    }

    // ── AgentVerdict tests ───────────────────────────────────────────────────

    fn sample_verdict(is_attack: bool) -> AgentVerdict {
        AgentVerdict {
            is_attack,
            confidence: if is_attack { 0.92 } else { 0.1 },
            attack_type: if is_attack {
                Some(AttackType::Reentrancy)
            } else {
                None
            },
            reasoning: "Multiple internal reverts detected at identical storage slots".to_string(),
            evidence: vec![
                "Revert count: 5".to_string(),
                "Storage slot 0x01 mutated 3 times".to_string(),
            ],
            evidence_valid: true,
            false_positive_reason: None,
            model_used: "claude-haiku-4-5-20251001".to_string(),
            tokens_used: 312,
            latency_ms: 450,
        }
    }

    #[test]
    fn agent_verdict_attack_roundtrip() {
        let verdict = sample_verdict(true);
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_attack);
        assert!((decoded.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(decoded.attack_type, Some(AttackType::Reentrancy));
        assert!(decoded.evidence_valid);
        assert_eq!(decoded.tokens_used, 312);
    }

    #[test]
    fn agent_verdict_non_attack_roundtrip() {
        let verdict = sample_verdict(false);
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_attack);
        assert!(decoded.attack_type.is_none());
    }

    #[test]
    fn agent_verdict_with_false_positive_reason() {
        let mut verdict = sample_verdict(false);
        verdict.false_positive_reason =
            Some("Known DeFi protocol internal rebalancing".to_string());

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.false_positive_reason.is_some());
    }

    #[test]
    fn agent_verdict_empty_evidence_serializes() {
        let mut verdict = sample_verdict(false);
        verdict.evidence = vec![];
        verdict.evidence_valid = false;

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.evidence.is_empty());
        assert!(!decoded.evidence_valid);
    }

    #[test]
    fn agent_verdict_other_attack_type() {
        let mut verdict = sample_verdict(true);
        verdict.attack_type = Some(AttackType::Other("governance attack".to_string()));

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.attack_type,
            Some(AttackType::Other("governance attack".to_string()))
        );
    }

    // ── CostTracker tests ────────────────────────────────────────────────────

    #[test]
    fn cost_tracker_default_values() {
        let tracker = CostTracker::default();
        assert_eq!(tracker.monthly_budget_usd, 150.0);
        assert_eq!(tracker.daily_limit_usd, 10.0);
        assert_eq!(tracker.hourly_rate_limit, 100);
        assert_eq!(tracker.max_concurrent_per_block, 3);
        assert!(!tracker.budget_exhausted);
    }

    #[test]
    fn cost_tracker_can_afford_within_budget() {
        let tracker = CostTracker::default();
        assert!(tracker.can_afford(0.005)); // typical Haiku request
        assert!(tracker.can_afford(0.02)); // typical Sonnet request
    }

    #[test]
    fn cost_tracker_cannot_afford_exceeds_monthly() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 149.99;
        assert!(!tracker.can_afford(0.02)); // would exceed $150
    }

    #[test]
    fn cost_tracker_cannot_afford_exceeds_daily() {
        let mut tracker = CostTracker::default();
        // today_cost_usd = 9.98, request = 0.05 → total 10.03, which exceeds $10 + epsilon
        tracker.today_cost_usd = 9.98;
        assert!(!tracker.can_afford(0.05)); // 9.98 + 0.05 = 10.03 > 10.01 (limit + epsilon)
    }

    #[test]
    fn cost_tracker_budget_exhausted_flag_blocks_all() {
        let mut tracker = CostTracker::default();
        tracker.budget_exhausted = true;
        assert!(!tracker.can_afford(0.001));
    }

    #[test]
    fn cost_tracker_record_updates_totals() {
        let mut tracker = CostTracker::default();
        tracker.record(0.005, 250, "claude-haiku-4-5-20251001");
        assert!((tracker.total_cost_usd - 0.005).abs() < f64::EPSILON);
        assert!((tracker.today_cost_usd - 0.005).abs() < f64::EPSILON);
        assert_eq!(tracker.total_tokens, 250);
        assert_eq!(tracker.request_count, 1);
        assert_eq!(tracker.haiku_requests, 1);
        assert_eq!(tracker.sonnet_requests, 0);
    }

    #[test]
    fn cost_tracker_record_sonnet() {
        let mut tracker = CostTracker::default();
        tracker.record(0.02, 500, "claude-sonnet-4-6");
        assert_eq!(tracker.sonnet_requests, 1);
        assert_eq!(tracker.haiku_requests, 0);
    }

    #[test]
    fn cost_tracker_sets_exhausted_at_budget_limit() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 149.99;
        tracker.record(0.01, 100, "claude-haiku-4-5-20251001");
        assert!(tracker.budget_exhausted);
    }

    #[test]
    fn cost_tracker_json_roundtrip() {
        let mut tracker = CostTracker::default();
        tracker.record(0.005, 250, "claude-haiku-4-5-20251001");
        tracker.last_daily_reset = "2026-03-05".to_string();
        tracker.last_monthly_reset = "2026-03-01".to_string();

        let json = serde_json::to_string(&tracker).unwrap();
        let decoded: CostTracker = serde_json::from_str(&json).unwrap();
        assert!((decoded.total_cost_usd - tracker.total_cost_usd).abs() < f64::EPSILON);
        assert_eq!(decoded.request_count, tracker.request_count);
        assert_eq!(decoded.last_daily_reset, "2026-03-05");
    }

    #[test]
    fn cost_tracker_multiple_records_accumulate() {
        let mut tracker = CostTracker::default();
        for _ in 0..10 {
            tracker.record(0.005, 250, "claude-haiku-4-5-20251001");
        }
        assert_eq!(tracker.request_count, 10);
        assert_eq!(tracker.haiku_requests, 10);
        assert_eq!(tracker.total_tokens, 2500);
        assert!((tracker.total_cost_usd - 0.05).abs() < 1e-10);
    }
}
