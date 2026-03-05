//! AiJudge — 2-tier AI pipeline (screening → deep analysis) with cost control.
//!
//! Like a hospital triage system: the screening model (fast, cheap) does an initial
//! assessment. If the patient looks critical (confidence >= threshold), they're
//! escalated to the specialist (deep model, slower, more expensive).
//!
//! Every call checks budget (CostTracker), rate limits, and circuit breaker status
//! before making an API request.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use super::ai_config::AiConfig;
use super::circuit_breaker::CircuitBreaker;
use super::client::{AiClient, AiError, AiResponse, TokenUsage};
use super::guard::validate_evidence;
use super::rate_limit::HourlyRateTracker;
use super::types::{AgentContext, AgentVerdict, CostTracker};

/// Worst-case estimated cost (USD) for a single AI request.
/// Used as a conservative budget check before making API calls.
const WORST_CASE_REQUEST_COST_USD: f64 = 0.02;

// ── Error ──────────────────────────────────────────────────────────────────

/// Errors from the AI Judge pipeline.
#[derive(Debug, thiserror::Error)]
pub enum JudgeError {
    #[error("Budget exhausted (monthly or daily limit reached)")]
    BudgetExhausted,
    #[error("Circuit breaker is open (consecutive API failures)")]
    CircuitBreakerOpen,
    #[error("Hourly rate limit exceeded")]
    RateLimitExceeded,
    #[error("AI client error: {0}")]
    AiError(#[from] AiError),
    #[error("All retries exhausted after {attempts} attempts: {last_error}")]
    RetriesExhausted { attempts: u32, last_error: String },
}

// ── AiJudge ────────────────────────────────────────────────────────────────

/// Two-tier AI judgment pipeline with cost control, rate limiting, and retry logic.
pub struct AiJudge<C: AiClient> {
    client: C,
    cost_tracker: Arc<Mutex<CostTracker>>,
    circuit_breaker: Arc<Mutex<CircuitBreaker>>,
    hourly_tracker: Arc<Mutex<HourlyRateTracker>>,
    config: AiConfig,
}

impl<C: AiClient> AiJudge<C> {
    /// Create a new AiJudge with the given client and configuration.
    pub fn new(client: C, cost_tracker: Arc<Mutex<CostTracker>>, config: AiConfig) -> Self {
        let circuit_breaker = Arc::new(Mutex::new(config.to_circuit_breaker()));
        let hourly_tracker = Arc::new(Mutex::new(config.to_hourly_tracker()));

        Self {
            client,
            cost_tracker,
            circuit_breaker,
            hourly_tracker,
            config,
        }
    }

    /// Run the 2-tier pipeline: screening → optional escalation → hallucination guard.
    ///
    /// Steps:
    /// 1. Pre-flight checks (budget, circuit breaker, rate limit)
    /// 2. Screening model call
    /// 3. If attack detected with confidence >= threshold, escalate to deep model
    /// 4. Run Hallucination Guard on final verdict
    /// 5. Record cost
    pub async fn judge(&self, context: &AgentContext) -> Result<AgentVerdict, JudgeError> {
        self.check_preflight().await?;

        // Step 1: Screening model
        let screening_response = self
            .call_with_retry(context, &self.config.screening_model)
            .await?;

        let screening_verdict = screening_response.verdict;
        let screening_usage = screening_response.usage;

        self.record_cost(&screening_usage, &self.config.screening_model)
            .await;

        // Step 2: Escalation check
        let should_escalate = screening_verdict.is_attack
            && screening_verdict.confidence >= self.config.is_suspicious_confidence_threshold;

        let (final_verdict, final_usage) = if should_escalate {
            // Check budget again before deep model call
            match self.check_preflight().await {
                Ok(()) => {
                    match self.call_with_retry(context, &self.config.deep_model).await {
                        Ok(deep_response) => {
                            self.record_cost(&deep_response.usage, &self.config.deep_model)
                                .await;
                            (deep_response.verdict, Some(deep_response.usage))
                        }
                        Err(_) => {
                            // Deep model failed — fall back to screening verdict
                            (screening_verdict, None)
                        }
                    }
                }
                Err(_) => {
                    // Budget exhausted for deep model — use screening result
                    (screening_verdict, None)
                }
            }
        } else {
            (screening_verdict, None)
        };

        // Step 3: Hallucination Guard
        let evidence_valid = validate_evidence(&final_verdict, context);

        if !evidence_valid {
            eprintln!(
                "[AI Judge] Hallucination Guard: evidence_valid=false for tx {:?}",
                context.tx_hash
            );
        }

        // Build final verdict with evidence_valid and combined token count
        let total_tokens = final_verdict.tokens_used
            + final_usage
                .as_ref()
                .map_or(0, |u| u.input_tokens + u.output_tokens);

        Ok(AgentVerdict {
            evidence_valid,
            tokens_used: if final_usage.is_some() {
                total_tokens
            } else {
                final_verdict.tokens_used
            },
            ..final_verdict
        })
    }

    /// Pre-flight checks: budget, circuit breaker, rate limit.
    async fn check_preflight(&self) -> Result<(), JudgeError> {
        // Check circuit breaker
        {
            let cb = self.circuit_breaker.lock().await;
            if cb.is_open() {
                return Err(JudgeError::CircuitBreakerOpen);
            }
        }

        // Check hourly rate limit
        {
            let tracker = self.hourly_tracker.lock().await;
            if !tracker.is_allowed() {
                return Err(JudgeError::RateLimitExceeded);
            }
        }

        // Check budget
        {
            let cost_tracker = self.cost_tracker.lock().await;
            if !cost_tracker.can_afford(WORST_CASE_REQUEST_COST_USD) {
                return Err(JudgeError::BudgetExhausted);
            }
        }

        Ok(())
    }

    /// Call the AI client with exponential backoff retry logic.
    async fn call_with_retry(
        &self,
        context: &AgentContext,
        model: &str,
    ) -> Result<AiResponse, JudgeError> {
        let max_retries = self.config.max_retries;
        let timeout = Duration::from_secs(self.config.request_timeout_secs);
        let mut last_error = String::new();

        for attempt in 0..=max_retries {
            if attempt > 0 {
                // Exponential backoff: 1s, 2s, 4s, ...
                let backoff = Duration::from_secs(1 << (attempt - 1));
                tokio::time::sleep(backoff).await;
            }

            // Record hourly rate (single lock scope to prevent race condition)
            {
                let mut tracker = self.hourly_tracker.lock().await;
                let updated = tracker.with_request_recorded();
                *tracker = updated;
            }

            let result = tokio::time::timeout(timeout, self.client.judge(context, model)).await;

            match result {
                Ok(Ok(response)) => {
                    // Record success on circuit breaker
                    self.circuit_breaker.lock().await.record_success();
                    return Ok(response);
                }
                Ok(Err(e)) => {
                    last_error = e.to_string();
                    let is_retryable = matches!(
                        &e,
                        AiError::Http(_)
                            | AiError::Api {
                                status: 429 | 500 | 502 | 503,
                                ..
                            }
                    );

                    if !is_retryable {
                        self.circuit_breaker.lock().await.record_failure();
                        return Err(JudgeError::AiError(e));
                    }
                    self.circuit_breaker.lock().await.record_failure();
                }
                Err(_timeout) => {
                    last_error = "request timed out".to_string();
                    self.circuit_breaker.lock().await.record_failure();
                }
            }
        }

        Err(JudgeError::RetriesExhausted {
            attempts: max_retries + 1,
            last_error,
        })
    }

    /// Record the cost of an API call.
    async fn record_cost(&self, usage: &TokenUsage, model: &str) {
        let cost = usage.cost_usd(model);
        let total_tokens = usage.input_tokens + usage.output_tokens;
        let mut tracker = self.cost_tracker.lock().await;
        tracker.record(cost, total_tokens, model);
    }

    /// Access the shared CostTracker (for metrics/reporting).
    pub fn cost_tracker(&self) -> &Arc<Mutex<CostTracker>> {
        &self.cost_tracker
    }

    /// Access the shared CircuitBreaker (for metrics/reporting).
    pub fn circuit_breaker(&self) -> &Arc<Mutex<CircuitBreaker>> {
        &self.circuit_breaker
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::ai::client::AiResponse;
    use crate::sentinel::ai::types::*;
    use ethrex_common::{Address, H256, U256};

    // ── Mock AI Client ─────────────────────────────────────────────────

    enum MockBehavior {
        Succeed(AgentVerdict),
        FailPermanent,
    }

    struct MockAiClient {
        behavior: MockBehavior,
    }

    impl MockAiClient {
        fn always_responding(verdict: AgentVerdict) -> Self {
            Self {
                behavior: MockBehavior::Succeed(verdict),
            }
        }

        fn failing_permanently() -> Self {
            Self {
                behavior: MockBehavior::FailPermanent,
            }
        }
    }

    fn mock_usage() -> TokenUsage {
        TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        }
    }

    impl AiClient for MockAiClient {
        async fn judge(
            &self,
            _context: &AgentContext,
            _model: &str,
        ) -> Result<AiResponse, AiError> {
            match &self.behavior {
                MockBehavior::Succeed(verdict) => Ok(AiResponse {
                    verdict: verdict.clone(),
                    usage: mock_usage(),
                }),
                MockBehavior::FailPermanent => Err(AiError::MissingApiKey),
            }
        }
    }

    // ── Test helpers ───────────────────────────────────────────────────

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

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

    fn benign_verdict() -> AgentVerdict {
        AgentVerdict {
            is_attack: false,
            confidence: 0.1,
            attack_type: None,
            reasoning: "Normal transaction".to_string(),
            evidence: vec!["Low gas usage pattern".to_string()],
            evidence_valid: false,
            false_positive_reason: Some("Standard swap".to_string()),
            model_used: "gemini-3-flash".to_string(),
            tokens_used: 500,
            latency_ms: 300,
        }
    }

    fn attack_verdict(confidence: f64) -> AgentVerdict {
        AgentVerdict {
            is_attack: true,
            confidence,
            attack_type: Some(AttackType::Reentrancy),
            reasoning: "Reentrancy detected".to_string(),
            evidence: vec!["Multiple internal reverts observed".to_string()],
            evidence_valid: false,
            false_positive_reason: None,
            model_used: "gemini-3-flash".to_string(),
            tokens_used: 500,
            latency_ms: 300,
        }
    }

    fn test_config() -> AiConfig {
        AiConfig {
            enabled: true,
            screening_model: "gemini-3-flash".to_string(),
            deep_model: "gemini-3-pro".to_string(),
            is_suspicious_confidence_threshold: 0.6,
            monthly_budget_usd: 150.0,
            daily_limit_usd: 10.0,
            hourly_rate_limit: 100,
            max_concurrent_per_block: 3,
            request_timeout_secs: 30,
            max_retries: 1, // Low for faster tests
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 600,
            ..Default::default()
        }
    }

    fn make_judge(client: MockAiClient) -> AiJudge<MockAiClient> {
        let config = test_config();
        let cost_tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        AiJudge::new(client, cost_tracker, config)
    }

    // ── Tests ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn judge_benign_returns_no_attack() {
        let client = MockAiClient::always_responding(benign_verdict());
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert!(!verdict.is_attack);
    }

    #[tokio::test]
    async fn judge_attack_below_threshold_no_escalation() {
        // Confidence 0.5 < threshold 0.6 → no escalation
        let client = MockAiClient::always_responding(attack_verdict(0.5));
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert!(verdict.is_attack);
        assert!((verdict.confidence - 0.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn judge_attack_above_threshold_triggers_escalation() {
        // Confidence 0.8 >= threshold 0.6 → escalation
        let client = MockAiClient::always_responding(attack_verdict(0.8));
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert!(verdict.is_attack);
        // Cost should reflect two API calls
        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 2);
    }

    #[tokio::test]
    async fn judge_budget_exhausted_returns_error() {
        let client = MockAiClient::always_responding(benign_verdict());
        let config = test_config();
        let mut tracker = config.to_cost_tracker();
        tracker.budget_exhausted = true;
        let cost_tracker = Arc::new(Mutex::new(tracker));
        let judge = AiJudge::new(client, cost_tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::BudgetExhausted)));
    }

    #[tokio::test]
    async fn judge_circuit_breaker_open_returns_error() {
        let client = MockAiClient::always_responding(benign_verdict());
        let judge = make_judge(client);

        // Trip the circuit breaker manually
        {
            let mut cb = judge.circuit_breaker().lock().await;
            for _ in 0..5 {
                cb.record_failure();
            }
        }

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::CircuitBreakerOpen)));
    }

    #[tokio::test]
    async fn judge_permanent_error_no_retry() {
        let client = MockAiClient::failing_permanently();
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::AiError(_))));
    }

    #[tokio::test]
    async fn judge_hallucination_guard_runs() {
        // Evidence is qualitative (no verifiable claims) → should pass guard
        let client = MockAiClient::always_responding(benign_verdict());
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        let verdict = result.unwrap();
        // "Low gas usage pattern" has no hex addresses/amounts → qualitative → passes
        assert!(verdict.evidence_valid);
    }

    #[tokio::test]
    async fn judge_records_cost() {
        let client = MockAiClient::always_responding(benign_verdict());
        let judge = make_judge(client);

        let _ = judge.judge(&minimal_context()).await;

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 1);
        assert!(tracker.total_cost_usd > 0.0);
    }
}
