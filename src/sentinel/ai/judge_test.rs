//! Additional tests for AiJudge — complements inline tests in judge.rs.
//!
//! Focuses on: escalation boundary, cost recording accuracy,
//! deep model fallback on failure, circuit breaker interaction,
//! and hallucination guard integration.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::sync::Mutex;

    use crate::sentinel::ai::AiConfig;
    use crate::sentinel::ai::client::{AiClient, AiError, AiResponse, TokenUsage};
    use crate::sentinel::ai::judge::{AiJudge, JudgeError};
    use crate::sentinel::ai::types::{AgentContext, AgentVerdict, AttackType};
    use ethrex_common::{Address, H256, U256};

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
            evidence: vec!["Low gas usage".to_string()],
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
            max_retries: 0, // No retries for faster tests
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 600,
            ..Default::default()
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

    // ── Counting Mock Client ─────────────────────────────────────────────

    struct CountingMockClient {
        verdict: AgentVerdict,
        call_count: AtomicU32,
        fail_on_call: Option<u32>,
    }

    impl CountingMockClient {
        fn new(verdict: AgentVerdict) -> Self {
            Self {
                verdict,
                call_count: AtomicU32::new(0),
                fail_on_call: None,
            }
        }

        fn failing_on_call(verdict: AgentVerdict, fail_on: u32) -> Self {
            Self {
                verdict,
                call_count: AtomicU32::new(0),
                fail_on_call: Some(fail_on),
            }
        }
    }

    impl AiClient for CountingMockClient {
        async fn judge(
            &self,
            _context: &AgentContext,
            _model: &str,
        ) -> Result<AiResponse, AiError> {
            let n = self.call_count.fetch_add(1, Ordering::Relaxed);

            if let Some(fail_on) = self.fail_on_call {
                if n >= fail_on {
                    return Err(AiError::Http("mock failure".to_string()));
                }
            }

            Ok(AiResponse {
                verdict: self.verdict.clone(),
                usage: mock_usage(),
            })
        }
    }

    fn make_judge(client: CountingMockClient) -> AiJudge<CountingMockClient> {
        let config = test_config();
        let tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        AiJudge::new(client, tracker, config)
    }

    // ── Escalation boundary tests ────────────────────────────────────────

    #[tokio::test]
    async fn benign_verdict_no_escalation() {
        let client = CountingMockClient::new(benign_verdict());
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_attack);
    }

    #[tokio::test]
    async fn attack_below_threshold_no_escalation() {
        // confidence 0.5 < threshold 0.6
        let client = CountingMockClient::new(attack_verdict(0.5));
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        let verdict = result.unwrap();
        assert!(verdict.is_attack);

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 1); // only screening
    }

    #[tokio::test]
    async fn attack_at_exact_threshold_triggers_escalation() {
        // confidence 0.6 == threshold 0.6
        let client = CountingMockClient::new(attack_verdict(0.6));
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 2); // screening + deep
    }

    #[tokio::test]
    async fn attack_above_threshold_triggers_escalation() {
        let client = CountingMockClient::new(attack_verdict(0.85));
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 2);
    }

    // ── Budget exhaustion ────────────────────────────────────────────────

    #[tokio::test]
    async fn budget_exhausted_returns_error() {
        let client = CountingMockClient::new(benign_verdict());
        let config = test_config();
        let mut tracker = config.to_cost_tracker();
        tracker.budget_exhausted = true;
        let cost_tracker = Arc::new(Mutex::new(tracker));
        let judge = AiJudge::new(client, cost_tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::BudgetExhausted)));
    }

    #[tokio::test]
    async fn daily_limit_exceeded_returns_error() {
        let client = CountingMockClient::new(benign_verdict());
        let config = test_config();
        let mut tracker = config.to_cost_tracker();
        tracker.today_cost_usd = 10.0; // at $10 daily limit
        let cost_tracker = Arc::new(Mutex::new(tracker));
        let judge = AiJudge::new(client, cost_tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::BudgetExhausted)));
    }

    // ── Circuit breaker ──────────────────────────────────────────────────

    #[tokio::test]
    async fn circuit_breaker_open_returns_error() {
        let client = CountingMockClient::new(benign_verdict());
        let judge = make_judge(client);

        {
            let mut cb = judge.circuit_breaker().lock().await;
            for _ in 0..5 {
                cb.record_failure();
            }
        }

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::CircuitBreakerOpen)));
    }

    // ── Deep model failure fallback ──────────────────────────────────────

    #[tokio::test]
    async fn deep_model_failure_falls_back_to_screening() {
        // Screening succeeds (call 0), deep model fails (call 1)
        let client = CountingMockClient::failing_on_call(attack_verdict(0.8), 1);
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());
        // Falls back to screening verdict
        let verdict = result.unwrap();
        assert!(verdict.is_attack);
    }

    // ── Cost recording accuracy ──────────────────────────────────────────

    #[tokio::test]
    async fn cost_recorded_after_screening() {
        let client = CountingMockClient::new(benign_verdict());
        let judge = make_judge(client);

        let _ = judge.judge(&minimal_context()).await;

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 1);
        assert!(tracker.total_cost_usd > 0.0);
        assert!(tracker.total_tokens > 0);
    }

    #[tokio::test]
    async fn cost_recorded_after_escalation() {
        let client = CountingMockClient::new(attack_verdict(0.9));
        let judge = make_judge(client);

        let _ = judge.judge(&minimal_context()).await;

        let tracker = judge.cost_tracker().lock().await;
        assert_eq!(tracker.request_count, 2);
    }

    // ── Hallucination guard runs on result ────────────────────────────────

    #[tokio::test]
    async fn verdict_has_evidence_valid_field_set() {
        let client = CountingMockClient::new(benign_verdict());
        let judge = make_judge(client);

        let result = judge.judge(&minimal_context()).await;
        let verdict = result.unwrap();
        // "Low gas usage" is qualitative (no hex refs) → soft pass
        assert!(verdict.evidence_valid);
    }

    // ── Permanent error not retried ──────────────────────────────────────

    #[tokio::test]
    async fn permanent_error_returns_immediately() {
        // MissingApiKey is not retryable
        struct AlwaysFailing;
        impl AiClient for AlwaysFailing {
            async fn judge(
                &self,
                _context: &AgentContext,
                _model: &str,
            ) -> Result<AiResponse, AiError> {
                Err(AiError::MissingApiKey)
            }
        }

        let config = test_config();
        let tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        let judge = AiJudge::new(AlwaysFailing, tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::AiError(_))));
    }
}
