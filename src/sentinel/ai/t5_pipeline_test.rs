//! T2: Pipeline AI integration tests (AiJudge mock).

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::super::AiConfig;
    use super::super::judge::{AiJudge, JudgeError};
    use super::super::t5_helpers::*;
    use ethrex_common::U256;

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
            max_retries: 0,
            circuit_breaker_threshold: 5,
            circuit_breaker_cooldown_secs: 600,
            ..Default::default()
        }
    }

    /// AI judge is called when feature is on and config is enabled.
    #[tokio::test]
    async fn pipeline_ai_judge_called_when_enabled() {
        let client = TrackingMockClient::new(benign_verdict());
        let config = test_config();
        let tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        let judge = AiJudge::new(client, tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());

        assert!(judge.cost_tracker().lock().await.request_count > 0);
    }

    /// AI judge returns error when budget is exhausted.
    #[tokio::test]
    async fn pipeline_ai_judge_skips_when_budget_exhausted() {
        let client = TrackingMockClient::new(benign_verdict());
        let config = test_config();
        let mut tracker = config.to_cost_tracker();
        tracker.budget_exhausted = true;
        let cost_tracker = Arc::new(Mutex::new(tracker));
        let judge = AiJudge::new(client, cost_tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(matches!(result, Err(JudgeError::BudgetExhausted)));
    }

    /// Verdict from AI judge is properly returned through pipeline.
    #[tokio::test]
    async fn pipeline_verdict_returned_correctly() {
        let client = TrackingMockClient::new(benign_verdict());
        let config = test_config();
        let tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        let judge = AiJudge::new(client, tracker, config);

        let verdict = judge.judge(&minimal_context()).await.unwrap();
        assert!(!verdict.is_attack);
        assert!(verdict.evidence_valid);
    }

    /// rpc_ai::init_ai_judge returns None when config is None.
    #[test]
    fn init_ai_judge_none_config() {
        assert!(crate::sentinel::rpc_ai::init_ai_judge(None).is_none());
    }

    /// rpc_ai::init_ai_judge returns None when disabled.
    #[test]
    fn init_ai_judge_disabled() {
        let config = AiConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(crate::sentinel::rpc_ai::init_ai_judge(Some(&config)).is_none());
    }

    /// ContextExtractor correctly uses call_input_selector from StepRecord.
    #[test]
    fn pipeline_context_extractor_uses_recorder_selector() {
        let target = addr(0xCC);
        let selector = [0xa9, 0x05, 0x9c, 0xbb];
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(68_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("input_selector"));
    }
}
