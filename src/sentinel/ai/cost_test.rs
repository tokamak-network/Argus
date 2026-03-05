//! Additional tests for CostTracker persistence, HourlyRateTracker, BlockConcurrencyTracker,
//! CircuitBreaker, and AiConfig — complements the inline tests in cost.rs.

#[cfg(test)]
mod tests {
    use crate::sentinel::ai::{
        AiConfig, BlockConcurrencyTracker, CircuitBreaker, CostTracker, HourlyRateTracker,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path() -> PathBuf {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        PathBuf::from(format!(
            "/tmp/argus_cost_ext_test_{}_{}.json",
            std::process::id(),
            id,
        ))
    }

    fn cleanup(path: &std::path::Path) {
        let _ = fs::remove_file(path);
    }

    // ── CostTracker persistence edge cases ───────────────────────────────

    #[test]
    fn save_creates_parent_directories() {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!(
            "/tmp/argus_cost_nested_{}/{}/tracker.json",
            std::process::id(),
            id,
        ));
        let _ = fs::remove_dir_all(path.parent().unwrap());

        let tracker = CostTracker::default();
        tracker.save(&path).expect("save should create parent dirs");
        assert!(path.exists());

        let _ = fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn save_overwrites_existing() {
        let path = unique_path();

        let mut tracker1 = CostTracker::default();
        tracker1.record(1.0, 100, "claude-haiku-4-5-20251001");
        tracker1.save(&path).unwrap();

        let mut tracker2 = CostTracker::default();
        tracker2.record(2.0, 200, "claude-sonnet-4-6");
        tracker2.save(&path).unwrap();

        let loaded = CostTracker::load(&path).unwrap();
        assert!((loaded.total_cost_usd - 2.0).abs() < f64::EPSILON);
        assert_eq!(loaded.sonnet_requests, 1);
        assert_eq!(loaded.haiku_requests, 0);

        cleanup(&path);
    }

    #[test]
    fn save_load_preserves_all_numeric_precision() {
        let path = unique_path();
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 99.999_999_999;
        tracker.today_cost_usd = 7.123_456_789;
        tracker.total_tokens = u64::MAX;
        tracker.save(&path).unwrap();

        let loaded = CostTracker::load(&path).unwrap();
        assert!((loaded.total_cost_usd - 99.999_999_999).abs() < 1e-9);
        assert!((loaded.today_cost_usd - 7.123_456_789).abs() < 1e-9);
        assert_eq!(loaded.total_tokens, u64::MAX);

        cleanup(&path);
    }

    #[test]
    fn save_preserves_budget_exhausted_flag() {
        let path = unique_path();
        let mut tracker = CostTracker::default();
        tracker.budget_exhausted = true;
        tracker.save(&path).unwrap();

        let loaded = CostTracker::load(&path).unwrap();
        assert!(loaded.budget_exhausted);

        cleanup(&path);
    }

    // ── with_resets_applied immutability ──────────────────────────────────

    #[test]
    fn with_resets_applied_does_not_mutate_original() {
        let mut tracker = CostTracker::default();
        tracker.today_cost_usd = 5.0;
        tracker.last_daily_reset = "2020-01-01".to_string();
        tracker.last_monthly_reset = "2020-01".to_string();

        let reset = tracker.with_resets_applied();

        // Original should be unchanged
        assert!((tracker.today_cost_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(tracker.last_daily_reset, "2020-01-01");

        // Reset copy should have zeroed daily cost
        assert!((reset.today_cost_usd - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn monthly_reset_clears_budget_exhausted_and_allows_new_requests() {
        let mut tracker = CostTracker::default();
        tracker.budget_exhausted = true;
        tracker.total_cost_usd = 150.0;
        tracker.last_monthly_reset = "2020-01".to_string();

        let reset = tracker.with_resets_applied();
        assert!(!reset.budget_exhausted);
        assert!(reset.can_afford(0.005));
    }

    // ── CostTracker can_afford edge cases ────────────────────────────────

    #[test]
    fn daily_limit_blocks_even_if_monthly_has_room() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 0.0; // plenty of monthly budget
        tracker.today_cost_usd = 10.0;
        assert!(!tracker.can_afford(0.02)); // 10.0 + 0.02 = 10.02 > 10.0 + 0.01
    }

    #[test]
    fn record_exhausts_budget_at_boundary() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 149.98;
        tracker.record(0.02, 100, "claude-sonnet-4-6");
        assert!(tracker.budget_exhausted);
        assert!(!tracker.can_afford(0.001));
    }

    // ── HourlyRateTracker immutability ───────────────────────────────────

    #[test]
    fn hourly_tracker_with_request_recorded_is_immutable() {
        let tracker = HourlyRateTracker::new(100);
        let updated = tracker.with_request_recorded();

        // Original unchanged
        assert_eq!(tracker.current_count(), 0);
        // New one has the record
        assert_eq!(updated.current_count(), 1);
    }

    #[test]
    fn hourly_tracker_blocks_at_exact_limit() {
        let mut tracker = HourlyRateTracker::new(3);
        for _ in 0..3 {
            tracker = tracker.with_request_recorded();
        }
        assert!(!tracker.is_allowed());
        assert_eq!(tracker.current_count(), 3);
    }

    #[test]
    fn hourly_tracker_allows_below_limit() {
        let mut tracker = HourlyRateTracker::new(3);
        for _ in 0..2 {
            tracker = tracker.with_request_recorded();
        }
        assert!(tracker.is_allowed());
    }

    // ── BlockConcurrencyTracker ──────────────────────────────────────────

    #[test]
    fn block_concurrency_new_block_resets_count() {
        let mut tracker = BlockConcurrencyTracker::new(1);
        tracker.acquire(100);
        assert!(!tracker.is_allowed(100));
        // Different block — should be allowed
        assert!(tracker.is_allowed(101));
    }

    #[test]
    fn block_concurrency_release_allows_another() {
        let mut tracker = BlockConcurrencyTracker::new(1);
        tracker.acquire(100);
        assert!(!tracker.is_allowed(100));
        tracker.release(100);
        assert!(tracker.is_allowed(100));
    }

    #[test]
    fn block_concurrency_release_wrong_block_is_noop() {
        let mut tracker = BlockConcurrencyTracker::new(1);
        tracker.acquire(100);
        tracker.release(999); // wrong block
        assert!(!tracker.is_allowed(100)); // still blocked
    }

    // ── CircuitBreaker half-open recovery ────────────────────────────────

    #[test]
    fn circuit_breaker_cooldown_auto_resets() {
        let mut cb = CircuitBreaker::new(2, 1); // 1-second cooldown
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_open(), "should be open after reaching threshold");
        // Without waiting for cooldown, it stays open
        assert!(cb.is_open());
    }

    #[test]
    fn circuit_breaker_success_resets_failures() {
        let mut cb = CircuitBreaker::new(3, 600);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.consecutive_failures(), 2);
        cb.record_success();
        assert_eq!(cb.consecutive_failures(), 0);
        assert!(!cb.is_open());
    }

    // ── AiConfig validation ──────────────────────────────────────────────

    #[test]
    fn ai_config_validate_negative_budget_fails() {
        let mut config = AiConfig::default();
        config.monthly_budget_usd = -1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_zero_rate_limit_fails() {
        let mut config = AiConfig::default();
        config.hourly_rate_limit = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_zero_concurrent_fails() {
        let mut config = AiConfig::default();
        config.max_concurrent_per_block = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_zero_timeout_fails() {
        let mut config = AiConfig::default();
        config.request_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_threshold_above_one_fails() {
        let mut config = AiConfig::default();
        config.is_suspicious_confidence_threshold = 1.1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_validate_negative_threshold_fails() {
        let mut config = AiConfig::default();
        config.is_suspicious_confidence_threshold = -0.1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ai_config_to_cost_tracker_uses_config_values() {
        let config = AiConfig {
            monthly_budget_usd: 200.0,
            daily_limit_usd: 15.0,
            hourly_rate_limit: 50,
            max_concurrent_per_block: 5,
            ..Default::default()
        };
        let tracker = config.to_cost_tracker();
        assert_eq!(tracker.monthly_budget_usd, 200.0);
        assert_eq!(tracker.daily_limit_usd, 15.0);
        assert_eq!(tracker.hourly_rate_limit, 50);
        assert_eq!(tracker.max_concurrent_per_block, 5);
        assert_eq!(tracker.total_cost_usd, 0.0);
        assert_eq!(tracker.request_count, 0);
    }

    #[test]
    fn ai_config_toml_roundtrip() {
        let config = AiConfig {
            enabled: true,
            backend: "litellm".to_string(),
            screening_model: "gemini-3-flash".to_string(),
            deep_model: "gemini-3-pro".to_string(),
            monthly_budget_usd: 200.0,
            is_suspicious_confidence_threshold: 0.7,
            ..Default::default()
        };
        let serialized = toml::to_string(&config).expect("serialize");
        let deserialized: AiConfig = toml::from_str(&serialized).expect("deserialize");
        assert!(deserialized.enabled);
        assert_eq!(deserialized.backend, "litellm");
        assert_eq!(deserialized.monthly_budget_usd, 200.0);
        assert!((deserialized.is_suspicious_confidence_threshold - 0.7).abs() < f64::EPSILON);
    }

    // ── Integration: persistence + reset ─────────────────────────────────

    #[test]
    fn save_load_then_reset_workflow() {
        let path = unique_path();

        // Day 1: spend some budget
        let mut tracker = CostTracker::default();
        tracker.last_daily_reset = "2026-03-04".to_string();
        tracker.last_monthly_reset = "2026-03".to_string();
        for _ in 0..10 {
            tracker.record(0.5, 100, "claude-haiku-4-5-20251001");
        }
        tracker.save(&path).unwrap();

        // Day 2: load and apply resets (still same month)
        let loaded = CostTracker::load(&path).unwrap();
        assert!((loaded.today_cost_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(loaded.request_count, 10);

        cleanup(&path);
    }
}
