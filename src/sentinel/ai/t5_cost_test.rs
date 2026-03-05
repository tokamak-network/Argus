//! T3: Cost persistence integration tests.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    use super::super::t5_helpers::*;
    use super::super::types::CostTracker;

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

    /// Atomic write: no tmp file left after successful save.
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
        use std::sync::atomic::AtomicU64;
        static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
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

        assert!((tracker.today_cost_usd - 5.0).abs() < f64::EPSILON);
        assert_eq!(tracker.last_daily_reset, "2020-01-01");
    }
}
