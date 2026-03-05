//! CostTracker — API cost tracking and monthly/daily budget enforcement.

use serde::{Deserialize, Serialize};

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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(tracker.can_afford(0.005));
        assert!(tracker.can_afford(0.02));
    }

    #[test]
    fn cost_tracker_cannot_afford_exceeds_monthly() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 149.99;
        assert!(!tracker.can_afford(0.02));
    }

    #[test]
    fn cost_tracker_cannot_afford_exceeds_daily() {
        let mut tracker = CostTracker::default();
        tracker.today_cost_usd = 9.98;
        assert!(!tracker.can_afford(0.05));
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
