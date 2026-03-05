//! T5: Integration tests for Phase 1 features.
//!
//! Covers: calldata capture (T1), pipeline AI integration (T2),
//! cost persistence (T3), and AI metrics (T4).

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::sync::Mutex;

    use crate::sentinel::ai::AiConfig;
    use crate::sentinel::ai::client::{AiClient, AiError, AiResponse, TokenUsage};
    use crate::sentinel::ai::context::{ContextExtractor, ExtractParams};
    use crate::sentinel::ai::judge::{AiJudge, JudgeError};
    use crate::sentinel::ai::types::{AgentContext, AgentVerdict, CallType, CostTracker};
    use crate::sentinel::metrics::SentinelMetrics;
    use crate::types::StepRecord;
    use ethrex_common::{Address, H256, U256};

    // ── Constants ────────────────────────────────────────────────────────────

    const OP_CALL: u8 = 0xF1;
    const OP_CALLCODE: u8 = 0xF2;
    const OP_DELEGATECALL: u8 = 0xF4;
    const OP_STATICCALL: u8 = 0xFA;
    const OP_ADD: u8 = 0x01;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn u256_addr(a: Address) -> U256 {
        let mut bytes = [0u8; 32];
        bytes[12..32].copy_from_slice(a.as_bytes());
        U256::from_big_endian(&bytes)
    }

    fn make_step(opcode: u8, depth: usize, code_addr: Address) -> StepRecord {
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

    fn extract(steps: &[StepRecord]) -> AgentContext {
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

    fn mock_usage() -> TokenUsage {
        TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        }
    }

    static PATH_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path() -> PathBuf {
        let id = PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(
            "/tmp/argus_t5_test_{}_{}.json",
            std::process::id(),
            id,
        ))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
    }

    // ── Mock AI Client ───────────────────────────────────────────────────────

    struct TrackingMockClient {
        verdict: AgentVerdict,
        call_count: AtomicU64,
    }

    impl TrackingMockClient {
        fn new(verdict: AgentVerdict) -> Self {
            Self {
                verdict,
                call_count: AtomicU64::new(0),
            }
        }
    }

    impl AiClient for TrackingMockClient {
        async fn judge(
            &self,
            _context: &AgentContext,
            _model: &str,
        ) -> Result<AiResponse, AiError> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            Ok(AiResponse {
                verdict: self.verdict.clone(),
                usage: mock_usage(),
            })
        }
    }

    // ========================================================================
    // T1: Calldata capture tests
    // ========================================================================

    /// CALL opcode with call_input_selector set should propagate to CallFrame.
    #[test]
    fn calldata_selector_propagated_for_call() {
        let target = addr(0xCC);
        let selector = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(68_u64), // argsLength >= 4
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::Call);
    }

    /// DELEGATECALL with selector propagates to both call_graph and delegatecalls.
    #[test]
    fn calldata_selector_propagated_for_delegatecall() {
        let target = addr(0xDD);
        let selector = [0x12, 0x34, 0x56, 0x78];
        let mut step = make_step(OP_DELEGATECALL, 1, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::from(36_u64), // argsLength >= 4
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::DelegateCall);
        assert_eq!(ctx.delegatecalls.len(), 1);
        assert_eq!(ctx.delegatecalls[0].input_selector, Some(selector));
    }

    /// STATICCALL with selector propagates correctly.
    #[test]
    fn calldata_selector_propagated_for_staticcall() {
        let target = addr(0xEE);
        let selector = [0xab, 0xcd, 0xef, 0x01];
        let mut step = make_step(OP_STATICCALL, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::from(4_u64), // argsLength == 4
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::StaticCall);
    }

    /// CALLCODE with selector propagates correctly.
    #[test]
    fn calldata_selector_propagated_for_callcode() {
        let target = addr(0xFF);
        let selector = [0xde, 0xad, 0xbe, 0xef];
        let mut step = make_step(OP_CALLCODE, 0, addr(0xBB));
        step.call_input_selector = Some(selector);
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(100_u64),
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));
        assert_eq!(ctx.call_graph[0].call_type, CallType::CallCode);
    }

    /// When call_input_selector is None (input < 4 bytes), CallFrame.input_selector is None.
    #[test]
    fn calldata_selector_none_when_input_too_short() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = None; // recorder saw < 4 bytes
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::from(2_u64), // argsLength < 4
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].input_selector.is_none());
    }

    /// Empty calldata (argsLength = 0) → None selector.
    #[test]
    fn calldata_selector_none_for_empty_calldata() {
        let target = addr(0xCC);
        let mut step = make_step(OP_CALL, 0, addr(0xBB));
        step.call_input_selector = None;
        step.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target),
            U256::zero(),
            U256::zero(),
            U256::zero(), // argsLength = 0
            U256::zero(),
            U256::from(32_u64),
        ];

        let ctx = extract(&[step]);
        assert_eq!(ctx.call_graph.len(), 1);
        assert!(ctx.call_graph[0].input_selector.is_none());
    }

    /// Non-call opcode (ADD) never has selector.
    #[test]
    fn calldata_selector_none_for_non_call_opcode() {
        let step = make_step(OP_ADD, 0, addr(0xBB));
        let ctx = extract(&[step]);
        assert!(ctx.call_graph.is_empty());
    }

    /// Mixed trace: some calls have selectors, some don't.
    #[test]
    fn calldata_selectors_mixed_in_trace() {
        let target1 = addr(0xC1);
        let target2 = addr(0xC2);

        let mut step1 = make_step(OP_CALL, 0, addr(0xBB));
        step1.call_input_selector = Some([0xaa, 0xbb, 0xcc, 0xdd]);
        step1.stack_top = vec![
            U256::from(50_000_u64),
            u256_addr(target1),
            U256::zero(),
            U256::zero(),
            U256::from(68_u64),
            U256::zero(),
            U256::zero(),
        ];

        let mut step2 = make_step(OP_STATICCALL, 1, target1);
        step2.call_input_selector = None; // no calldata
        step2.stack_top = vec![
            U256::from(30_000_u64),
            u256_addr(target2),
            U256::zero(),
            U256::zero(), // argsLength = 0
            U256::zero(),
            U256::zero(),
        ];

        let ctx = extract(&[step1, step2]);
        assert_eq!(ctx.call_graph.len(), 2);
        assert_eq!(
            ctx.call_graph[0].input_selector,
            Some([0xaa, 0xbb, 0xcc, 0xdd])
        );
        assert!(ctx.call_graph[1].input_selector.is_none());
    }

    // ========================================================================
    // T2: Pipeline integration tests (AiJudge mock)
    // ========================================================================

    /// AI judge is called when feature is on and config is enabled.
    #[tokio::test]
    async fn pipeline_ai_judge_called_when_enabled() {
        let client = TrackingMockClient::new(benign_verdict());
        let config = test_config();
        let tracker = Arc::new(Mutex::new(config.to_cost_tracker()));
        let judge = AiJudge::new(client, tracker, config);

        let result = judge.judge(&minimal_context()).await;
        assert!(result.is_ok());

        // Verify the client was actually called
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
        assert!(verdict.evidence_valid); // hallucination guard runs
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

    /// ContextExtractor correctly uses call_input_selector from StepRecord
    /// for the AI pipeline context.
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
        // The AI context should have the selector from the recorder
        assert_eq!(ctx.call_graph[0].input_selector, Some(selector));

        // Serialized JSON should contain the selector
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("input_selector"));
    }

    // ========================================================================
    // T3: Cost persistence tests
    // ========================================================================

    /// Save → Load roundtrip preserves all fields.
    #[test]
    fn cost_save_load_roundtrip_all_fields() {
        let path = unique_path();

        let mut tracker = CostTracker::default();
        tracker.record(1.5, 300, "claude-haiku-4-5-20251001");
        tracker.record(2.0, 500, "claude-sonnet-4-6");
        tracker.last_daily_reset = "2026-03-05".to_string();
        tracker.last_monthly_reset = "2026-03".to_string();

        tracker.save(&path).unwrap();
        let loaded = CostTracker::load(&path).unwrap();

        assert!((loaded.total_cost_usd - 3.5).abs() < 1e-10);
        assert!((loaded.today_cost_usd - 3.5).abs() < 1e-10);
        assert_eq!(loaded.total_tokens, 800);
        assert_eq!(loaded.request_count, 2);
        assert_eq!(loaded.haiku_requests, 1);
        assert_eq!(loaded.sonnet_requests, 1);
        assert_eq!(loaded.last_daily_reset, "2026-03-05");
        assert_eq!(loaded.last_monthly_reset, "2026-03");
        assert!(!loaded.budget_exhausted);

        cleanup(&path);
    }

    /// Daily reset zeroes today_cost but preserves total.
    #[test]
    fn cost_daily_reset_preserves_total() {
        use crate::sentinel::ai::cost::current_month_string;

        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 50.0;
        tracker.today_cost_usd = 8.0;
        tracker.last_daily_reset = "2020-01-01".to_string();
        tracker.last_monthly_reset = current_month_string();

        let reset = tracker.with_resets_applied();
        assert!((reset.today_cost_usd - 0.0).abs() < f64::EPSILON);
        assert!((reset.total_cost_usd - 50.0).abs() < f64::EPSILON);
    }

    /// Monthly reset zeroes everything and clears budget_exhausted.
    #[test]
    fn cost_monthly_reset_clears_all() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 149.0;
        tracker.today_cost_usd = 9.0;
        tracker.total_tokens = 50_000;
        tracker.request_count = 1000;
        tracker.haiku_requests = 800;
        tracker.sonnet_requests = 200;
        tracker.budget_exhausted = true;
        tracker.last_monthly_reset = "2020-01".to_string();

        let reset = tracker.with_resets_applied();
        assert!((reset.total_cost_usd - 0.0).abs() < f64::EPSILON);
        assert!((reset.today_cost_usd - 0.0).abs() < f64::EPSILON);
        assert_eq!(reset.total_tokens, 0);
        assert_eq!(reset.request_count, 0);
        assert_eq!(reset.haiku_requests, 0);
        assert_eq!(reset.sonnet_requests, 0);
        assert!(!reset.budget_exhausted);
    }

    /// Loading a nonexistent file returns default tracker.
    #[test]
    fn cost_load_nonexistent_returns_default() {
        let path = PathBuf::from(format!(
            "/tmp/argus_t5_nonexistent_{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);

        let tracker = CostTracker::load(&path).unwrap();
        assert_eq!(tracker.monthly_budget_usd, 150.0);
        assert_eq!(tracker.daily_limit_usd, 10.0);
        assert_eq!(tracker.request_count, 0);
        assert_eq!(tracker.total_cost_usd, 0.0);
    }

    /// Atomic write: no .json.{pid}.tmp file left after successful save.
    #[test]
    fn cost_atomic_write_no_tmp_left() {
        let path = unique_path();
        let tmp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));

        let tracker = CostTracker::default();
        tracker.save(&path).unwrap();

        assert!(path.exists(), "target file should exist");
        assert!(
            !tmp_path.exists(),
            "tmp file should be cleaned up by rename"
        );

        cleanup(&path);
    }

    /// Save creates parent directories.
    #[test]
    fn cost_save_creates_parent_dirs() {
        let id = PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/tmp/argus_t5_nested_{}/{}/tracker.json",
            std::process::id(),
            id,
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());

        let tracker = CostTracker::default();
        tracker.save(&path).expect("save should create parent dirs");
        assert!(path.exists());

        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    /// Overwriting an existing file with a new save works correctly.
    #[test]
    fn cost_save_overwrites_existing() {
        let path = unique_path();

        let mut tracker1 = CostTracker::default();
        tracker1.record(1.0, 100, "claude-haiku-4-5-20251001");
        tracker1.save(&path).unwrap();

        let mut tracker2 = CostTracker::default();
        tracker2.record(5.0, 500, "claude-sonnet-4-6");
        tracker2.save(&path).unwrap();

        let loaded = CostTracker::load(&path).unwrap();
        assert!((loaded.total_cost_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(loaded.sonnet_requests, 1);
        assert_eq!(loaded.haiku_requests, 0);

        cleanup(&path);
    }

    /// with_resets_applied is immutable — doesn't change the original.
    #[test]
    fn cost_resets_immutable() {
        let mut tracker = CostTracker::default();
        tracker.today_cost_usd = 5.0;
        tracker.last_daily_reset = "2020-01-01".to_string();
        tracker.last_monthly_reset = "2020-01".to_string();

        let _reset = tracker.with_resets_applied();

        // Original is untouched
        assert!((tracker.today_cost_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(tracker.last_daily_reset, "2020-01-01");
    }

    // ========================================================================
    // T4: Metrics tests — AI metrics in Prometheus output
    // ========================================================================

    /// AI metrics appear in Prometheus text with ai_agent feature.
    #[test]
    fn metrics_ai_fields_in_prometheus_output() {
        let metrics = SentinelMetrics::new();

        metrics.increment_ai_screening_requests();
        metrics.increment_ai_screening_requests();
        metrics.increment_ai_escalation_requests();
        metrics.add_ai_request_latency_ms(150);
        metrics.add_ai_cost_usd(0.005);
        metrics.increment_ai_attacks_detected();
        metrics.increment_ai_escalations_total();
        metrics.set_ai_circuit_breaker_open(false);

        let text = metrics.to_prometheus_text();

        // Verify AI metrics are present
        assert!(
            text.contains("sentinel_ai_requests_total"),
            "should contain ai_requests_total"
        );
        assert!(
            text.contains("sentinel_ai_requests_total{model=\"screening\"} 2"),
            "screening requests should be 2"
        );
        assert!(
            text.contains("sentinel_ai_requests_total{model=\"escalation\"} 1"),
            "escalation requests should be 1"
        );
        assert!(
            text.contains("sentinel_ai_request_latency_ms_sum 150"),
            "latency sum should be 150"
        );
        assert!(
            text.contains("sentinel_ai_request_latency_ms_count 1"),
            "latency count should be 1"
        );
        assert!(
            text.contains("sentinel_ai_cost_usd_total"),
            "should contain ai_cost"
        );
        assert!(
            text.contains("sentinel_ai_attacks_detected 1"),
            "attacks detected should be 1"
        );
        assert!(
            text.contains("sentinel_ai_escalations_total 1"),
            "escalations should be 1"
        );
        assert!(
            text.contains("sentinel_ai_circuit_breaker_open 0"),
            "circuit breaker should be closed (0)"
        );
    }

    /// AI metrics at zero state are still present in Prometheus output.
    #[test]
    fn metrics_ai_fields_zero_state() {
        let metrics = SentinelMetrics::new();
        let text = metrics.to_prometheus_text();

        assert!(text.contains("sentinel_ai_requests_total{model=\"screening\"} 0"));
        assert!(text.contains("sentinel_ai_requests_total{model=\"escalation\"} 0"));
        assert!(text.contains("sentinel_ai_request_latency_ms_sum 0"));
        assert!(text.contains("sentinel_ai_request_latency_ms_count 0"));
        assert!(text.contains("sentinel_ai_attacks_detected 0"));
        assert!(text.contains("sentinel_ai_escalations_total 0"));
        assert!(text.contains("sentinel_ai_circuit_breaker_open 0"));
    }

    /// AI cost conversion from f64 to micro-USD is accurate.
    #[test]
    fn metrics_ai_cost_micro_usd_conversion() {
        let metrics = SentinelMetrics::new();

        metrics.add_ai_cost_usd(0.005);
        metrics.add_ai_cost_usd(0.015);

        let text = metrics.to_prometheus_text();
        // 0.005 + 0.015 = 0.020 USD = 20000 micro-USD
        assert!(
            text.contains("sentinel_ai_cost_usd_total 0.020000"),
            "cost should be $0.020000, got: {}",
            text.lines()
                .find(|l| l.contains("sentinel_ai_cost_usd_total"))
                .unwrap_or("NOT FOUND")
        );
    }

    /// Circuit breaker gauge toggles correctly.
    #[test]
    fn metrics_ai_circuit_breaker_toggle() {
        let metrics = SentinelMetrics::new();

        metrics.set_ai_circuit_breaker_open(true);
        let text1 = metrics.to_prometheus_text();
        assert!(text1.contains("sentinel_ai_circuit_breaker_open 1"));

        metrics.set_ai_circuit_breaker_open(false);
        let text2 = metrics.to_prometheus_text();
        assert!(text2.contains("sentinel_ai_circuit_breaker_open 0"));
    }

    /// AI metrics have correct Prometheus TYPE annotations.
    #[test]
    fn metrics_ai_type_annotations() {
        let metrics = SentinelMetrics::new();
        let text = metrics.to_prometheus_text();

        assert!(text.contains("# TYPE sentinel_ai_requests_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_request_latency_ms summary"));
        assert!(text.contains("# TYPE sentinel_ai_cost_usd_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_attacks_detected counter"));
        assert!(text.contains("# TYPE sentinel_ai_escalations_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_circuit_breaker_open gauge"));
    }

    /// Snapshot includes AI metrics.
    #[test]
    fn metrics_snapshot_includes_ai_fields() {
        let metrics = SentinelMetrics::new();
        metrics.increment_ai_screening_requests();
        metrics.increment_ai_escalation_requests();
        metrics.add_ai_request_latency_ms(200);
        metrics.add_ai_cost_usd(0.01);
        metrics.increment_ai_attacks_detected();

        let snap = metrics.snapshot();
        assert_eq!(snap.ai_screening_requests, 1);
        assert_eq!(snap.ai_escalation_requests, 1);
        assert_eq!(snap.ai_request_latency_total_ms, 200);
        assert_eq!(snap.ai_request_latency_count, 1);
        assert_eq!(snap.ai_cost_micro_usd_total, 10_000); // 0.01 * 1e6
        assert_eq!(snap.ai_attacks_detected, 1);
    }

    /// Concurrent AI metric increments are safe.
    #[test]
    fn metrics_ai_concurrent_safety() {
        let metrics = Arc::new(SentinelMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let m = metrics.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    m.increment_ai_screening_requests();
                    m.increment_ai_escalation_requests();
                    m.add_ai_request_latency_ms(1);
                    m.add_ai_cost_usd(0.001);
                    m.increment_ai_attacks_detected();
                    m.increment_ai_escalations_total();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let snap = metrics.snapshot();
        assert_eq!(snap.ai_screening_requests, 2000);
        assert_eq!(snap.ai_escalation_requests, 2000);
        assert_eq!(snap.ai_request_latency_total_ms, 2000);
        assert_eq!(snap.ai_request_latency_count, 2000);
        assert_eq!(snap.ai_attacks_detected, 2000);
        assert_eq!(snap.ai_escalations_total, 2000);
    }
}
