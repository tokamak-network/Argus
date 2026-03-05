//! CostTracker file-based persistence and daily/monthly resets.

use std::path::Path;

use super::types::CostTracker;

// ── Error ──────────────────────────────────────────────────────────────────

/// Errors from CostTracker persistence operations.
#[derive(Debug, thiserror::Error)]
pub enum CostError {
    #[error("Failed to read cost tracker file: {0}")]
    ReadError(String),
    #[error("Failed to write cost tracker file: {0}")]
    WriteError(String),
    #[error("Failed to parse cost tracker JSON: {0}")]
    ParseError(String),
}

// ── CostTracker persistence ────────────────────────────────────────────────

/// Get today's date as an ISO-8601 string (YYYY-MM-DD).
pub(crate) fn today_date_string() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Get current month as YYYY-MM string.
pub(crate) fn current_month_string() -> String {
    let date = today_date_string();
    date[..7].to_string()
}

/// Convert days since Unix epoch to (year, month, day).
/// Uses the Howard Hinnant civil calendar algorithm.
pub(crate) fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

impl CostTracker {
    /// Load a CostTracker from a JSON file. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, CostError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents =
            std::fs::read_to_string(path).map_err(|e| CostError::ReadError(e.to_string()))?;
        let tracker: Self =
            serde_json::from_str(&contents).map_err(|e| CostError::ParseError(e.to_string()))?;
        Ok(tracker)
    }

    /// Save the CostTracker to a JSON file using atomic write (tmp + rename).
    ///
    /// Creates parent directories if needed. The rename ensures readers never
    /// see a partially-written file.
    pub fn save(&self, path: &Path) -> Result<(), CostError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CostError::WriteError(e.to_string()))?;
        }
        let json = serde_json::to_string(self).map_err(|e| CostError::WriteError(e.to_string()))?;

        let tmp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp_path, &json).map_err(|e| CostError::WriteError(e.to_string()))?;
        std::fs::rename(&tmp_path, path).map_err(|e| {
            // Clean up tmp on rename failure
            let _ = std::fs::remove_file(&tmp_path);
            CostError::WriteError(e.to_string())
        })?;
        Ok(())
    }

    /// Check and perform daily/monthly resets if dates have changed.
    /// Returns a new CostTracker with resets applied (immutable pattern).
    pub fn with_resets_applied(&self) -> Self {
        let today = today_date_string();
        let month = current_month_string();
        let mut result = self.clone();

        // Monthly reset: if the month has changed, reset everything
        if result.last_monthly_reset != month {
            result.total_cost_usd = 0.0;
            result.today_cost_usd = 0.0;
            result.total_tokens = 0;
            result.request_count = 0;
            result.haiku_requests = 0;
            result.sonnet_requests = 0;
            result.budget_exhausted = false;
            result.last_monthly_reset = month;
            result.last_daily_reset = today;
            return result;
        }

        // Daily reset: if the date has changed, reset daily counter
        if result.last_daily_reset != today {
            result.today_cost_usd = 0.0;
            result.last_daily_reset = today;
        }

        result
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_tracker_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("argus_test_cost");
        let path = dir.join("cost_tracker.json");
        let _ = std::fs::remove_file(&path);

        let mut tracker = CostTracker::default();
        tracker.record(0.005, 250, "claude-haiku-4-5-20251001");
        tracker.last_daily_reset = "2026-03-05".to_string();
        tracker.last_monthly_reset = "2026-03".to_string();

        tracker.save(&path).unwrap();
        let loaded = CostTracker::load(&path).unwrap();

        assert!((loaded.total_cost_usd - 0.005).abs() < f64::EPSILON);
        assert_eq!(loaded.request_count, 1);
        assert_eq!(loaded.last_daily_reset, "2026-03-05");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn cost_tracker_load_nonexistent_returns_default() {
        let path = std::env::temp_dir().join("argus_nonexistent_cost.json");
        let tracker = CostTracker::load(&path).unwrap();
        assert_eq!(tracker.monthly_budget_usd, 150.0);
        assert_eq!(tracker.request_count, 0);
    }

    #[test]
    fn cost_tracker_daily_reset() {
        let mut tracker = CostTracker::default();
        tracker.today_cost_usd = 5.0;
        tracker.last_daily_reset = "2020-01-01".to_string();
        tracker.last_monthly_reset = current_month_string();

        let reset = tracker.with_resets_applied();
        assert!((reset.today_cost_usd - 0.0).abs() < f64::EPSILON);
        assert_eq!(reset.last_daily_reset, today_date_string());
    }

    #[test]
    fn cost_tracker_monthly_reset() {
        let mut tracker = CostTracker::default();
        tracker.total_cost_usd = 100.0;
        tracker.today_cost_usd = 5.0;
        tracker.request_count = 500;
        tracker.budget_exhausted = true;
        tracker.last_monthly_reset = "2020-01".to_string();

        let reset = tracker.with_resets_applied();
        assert!((reset.total_cost_usd - 0.0).abs() < f64::EPSILON);
        assert!((reset.today_cost_usd - 0.0).abs() < f64::EPSILON);
        assert_eq!(reset.request_count, 0);
        assert!(!reset.budget_exhausted);
    }

    #[test]
    fn cost_tracker_no_reset_same_day() {
        let mut tracker = CostTracker::default();
        tracker.today_cost_usd = 5.0;
        tracker.last_daily_reset = today_date_string();
        tracker.last_monthly_reset = current_month_string();

        let reset = tracker.with_resets_applied();
        assert!((reset.today_cost_usd - 5.0).abs() < f64::EPSILON);
    }

    // ── Date helpers ────────────────────────────────────────────────────

    #[test]
    fn today_date_string_format() {
        let date = today_date_string();
        assert_eq!(date.len(), 10);
        assert_eq!(date.as_bytes()[4], b'-');
        assert_eq!(date.as_bytes()[7], b'-');
    }

    #[test]
    fn current_month_string_format() {
        let month = current_month_string();
        assert_eq!(month.len(), 7);
        assert_eq!(month.as_bytes()[4], b'-');
    }

    #[test]
    fn days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        let (y, m, d) = days_to_ymd(20517);
        assert_eq!((y, m, d), (2026, 3, 5));
    }

    #[test]
    fn days_to_ymd_leap_year() {
        // 2024-02-29 = 19782 days since epoch
        let (y, m, d) = days_to_ymd(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn days_to_ymd_year_boundary() {
        // 2025-12-31 = 20453 days since epoch
        let (y, m, d) = days_to_ymd(20453);
        assert_eq!((y, m, d), (2025, 12, 31));
        // Next day: 2026-01-01
        let (y2, m2, d2) = days_to_ymd(20454);
        assert_eq!((y2, m2, d2), (2026, 1, 1));
    }
}
