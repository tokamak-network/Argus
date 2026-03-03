//! Historical alert query engine for the Sentinel system.
//!
//! Reads alerts from JSONL files written by [`super::alert::JsonlFileAlertHandler`]
//! and provides paginated, filterable access for the dashboard and CLI.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::types::{AlertPriority, SentinelAlert};

/// Sort order for alert query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SortOrder {
    /// Most recent block first (descending block_number).
    Newest,
    /// Oldest block first (ascending block_number).
    Oldest,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self::Newest
    }
}

/// Parameters for querying historical alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertQueryParams {
    /// 1-based page number.
    pub page: usize,
    /// Items per page (default 20, max 100).
    pub page_size: usize,
    /// Filter: only include alerts at or above this priority level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_priority: Option<AlertPriority>,
    /// Filter: only include alerts within this block number range (inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_range: Option<(u64, u64)>,
    /// Filter: only include alerts containing this attack pattern name.
    /// Only effective when the `autopsy` feature is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern_type: Option<String>,
    /// Sort order (default: Newest first).
    pub sort_order: SortOrder,
}

impl Default for AlertQueryParams {
    fn default() -> Self {
        Self {
            page: 1,
            page_size: 20,
            min_priority: None,
            block_range: None,
            pattern_type: None,
            sort_order: SortOrder::default(),
        }
    }
}

/// Result of a historical alert query.
#[derive(Debug, Clone, Serialize)]
pub struct AlertQueryResult {
    /// Alerts on the requested page.
    pub alerts: Vec<SentinelAlert>,
    /// Total number of alerts matching the filters (before pagination).
    pub total_count: usize,
    /// Current page (1-based).
    pub page: usize,
    /// Items per page.
    pub page_size: usize,
    /// Total number of pages.
    pub total_pages: usize,
}

/// Reads historical alerts from a JSONL file and supports filtered queries.
pub struct AlertHistory {
    jsonl_path: PathBuf,
}

impl AlertHistory {
    /// Create a new history reader for the given JSONL file path.
    pub fn new(jsonl_path: PathBuf) -> Self {
        Self { jsonl_path }
    }

    /// Query alerts with filtering, sorting, and pagination.
    ///
    /// Reads the entire JSONL file, applies filters, sorts, and returns
    /// the requested page. Returns an empty result if the file does not
    /// exist or cannot be opened.
    pub fn query(&self, params: &AlertQueryParams) -> AlertQueryResult {
        let page_size = params.page_size.clamp(1, 100);
        let page = params.page.max(1);

        let alerts = self.read_all_alerts();

        let filtered: Vec<SentinelAlert> = alerts
            .into_iter()
            .filter(|a| self.matches_priority(a, &params.min_priority))
            .filter(|a| self.matches_block_range(a, &params.block_range))
            .filter(|a| self.matches_pattern_type(a, &params.pattern_type))
            .collect();

        let total_count = filtered.len();
        let total_pages = if total_count == 0 {
            0
        } else {
            total_count.div_ceil(page_size)
        };

        let mut sorted = filtered;
        match params.sort_order {
            SortOrder::Newest => sorted.sort_by(|a, b| b.block_number.cmp(&a.block_number)),
            SortOrder::Oldest => sorted.sort_by(|a, b| a.block_number.cmp(&b.block_number)),
        }

        let skip = (page - 1) * page_size;
        let page_alerts: Vec<SentinelAlert> =
            sorted.into_iter().skip(skip).take(page_size).collect();

        AlertQueryResult {
            alerts: page_alerts,
            total_count,
            page,
            page_size,
            total_pages,
        }
    }

    /// Read and parse all valid alerts from the JSONL file.
    fn read_all_alerts(&self) -> Vec<SentinelAlert> {
        let file = match File::open(&self.jsonl_path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let reader = BufReader::new(file);
        let mut alerts = Vec::new();

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match serde_json::from_str::<SentinelAlert>(trimmed) {
                Ok(alert) => alerts.push(alert),
                Err(_) => {
                    // Skip malformed lines silently
                    continue;
                }
            }
        }

        alerts
    }

    /// Check if an alert meets the minimum priority filter.
    fn matches_priority(
        &self,
        alert: &SentinelAlert,
        min_priority: &Option<AlertPriority>,
    ) -> bool {
        let min = match min_priority {
            Some(p) => p,
            None => return true,
        };
        priority_rank(&alert.alert_priority) >= priority_rank(min)
    }

    /// Check if an alert falls within the block range filter.
    fn matches_block_range(&self, alert: &SentinelAlert, block_range: &Option<(u64, u64)>) -> bool {
        let (start, end) = match block_range {
            Some(range) => *range,
            None => return true,
        };
        alert.block_number >= start && alert.block_number <= end
    }

    /// Check if an alert contains the requested attack pattern type.
    ///
    /// Only functional when the `autopsy` feature is enabled.
    /// Without `autopsy`, this filter is a no-op (all alerts pass).
    fn matches_pattern_type(&self, alert: &SentinelAlert, pattern_type: &Option<String>) -> bool {
        let target = match pattern_type {
            Some(p) => p,
            None => return true,
        };

        self.check_pattern_match(alert, target)
    }

    #[cfg(feature = "autopsy")]
    fn check_pattern_match(&self, alert: &SentinelAlert, target: &str) -> bool {
        if alert.detected_patterns.is_empty() {
            return false;
        }
        alert.detected_patterns.iter().any(|dp| {
            let name = match &dp.pattern {
                crate::autopsy::types::AttackPattern::Reentrancy { .. } => "Reentrancy",
                crate::autopsy::types::AttackPattern::FlashLoan { .. } => "FlashLoan",
                crate::autopsy::types::AttackPattern::PriceManipulation { .. } => {
                    "PriceManipulation"
                }
                crate::autopsy::types::AttackPattern::AccessControlBypass { .. } => {
                    "AccessControlBypass"
                }
            };
            name.eq_ignore_ascii_case(target)
        })
    }

    #[cfg(not(feature = "autopsy"))]
    fn check_pattern_match(&self, _alert: &SentinelAlert, _target: &str) -> bool {
        true
    }
}

/// Numeric rank for priority comparison (higher = more severe).
fn priority_rank(priority: &AlertPriority) -> u8 {
    match priority {
        AlertPriority::Medium => 1,
        AlertPriority::High => 2,
        AlertPriority::Critical => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{H256, U256};
    use std::io::Write;

    /// Create a test alert with configurable block number, priority, and tx hash byte.
    fn make_alert(block_number: u64, priority: AlertPriority, tx_hash_byte: u8) -> SentinelAlert {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = tx_hash_byte;
        SentinelAlert {
            block_number,
            block_hash: H256::zero(),
            tx_hash: H256::from(hash_bytes),
            tx_index: 0,
            alert_priority: priority,
            suspicion_reasons: vec![],
            suspicion_score: match priority {
                AlertPriority::Critical => 0.9,
                AlertPriority::High => 0.6,
                AlertPriority::Medium => 0.4,
            },
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: format!("Test alert at block {}", block_number),
            total_steps: 100,
            feature_vector: None,
        }
    }

    /// Counter for unique test file names.
    static TEST_FILE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Write alerts to a temporary JSONL file and return the path.
    fn write_jsonl(alerts: &[SentinelAlert]) -> PathBuf {
        let dir = std::env::temp_dir().join("sentinel_history_tests");
        let _ = std::fs::create_dir_all(&dir);
        let id = TEST_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = dir.join(format!("test_{}_{}.jsonl", std::process::id(), id));

        let mut file = std::fs::File::create(&path).expect("create test file");
        for alert in alerts {
            let json = serde_json::to_string(alert).expect("serialize alert");
            writeln!(file, "{}", json).expect("write line");
        }

        path
    }

    #[test]
    fn history_basic_read() {
        let alerts = vec![
            make_alert(100, AlertPriority::High, 0x01),
            make_alert(101, AlertPriority::Medium, 0x02),
            make_alert(102, AlertPriority::Critical, 0x03),
        ];
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 3);
        assert_eq!(result.alerts.len(), 3);
        assert_eq!(result.page, 1);
        assert_eq!(result.page_size, 20);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_empty_file() {
        let path = write_jsonl(&[]);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 0);
        assert!(result.alerts.is_empty());
        assert_eq!(result.total_pages, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_missing_file() {
        let history = AlertHistory::new(PathBuf::from("/nonexistent/path/alerts.jsonl"));

        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 0);
        assert!(result.alerts.is_empty());
    }

    #[test]
    fn history_pagination_page1() {
        let alerts: Vec<SentinelAlert> = (0..5)
            .map(|i| make_alert(100 + i, AlertPriority::High, i as u8))
            .collect();
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            page: 1,
            page_size: 2,
            ..Default::default()
        });

        assert_eq!(result.total_count, 5);
        assert_eq!(result.alerts.len(), 2);
        assert_eq!(result.page, 1);
        assert_eq!(result.total_pages, 3);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_pagination_page2() {
        let alerts: Vec<SentinelAlert> = (0..5)
            .map(|i| make_alert(100 + i, AlertPriority::High, i as u8))
            .collect();
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            page: 2,
            page_size: 2,
            ..Default::default()
        });

        assert_eq!(result.total_count, 5);
        assert_eq!(result.alerts.len(), 2);
        assert_eq!(result.page, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_pagination_out_of_range() {
        let alerts: Vec<SentinelAlert> = (0..3)
            .map(|i| make_alert(100 + i, AlertPriority::High, i as u8))
            .collect();
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            page: 100,
            page_size: 20,
            ..Default::default()
        });

        assert_eq!(result.total_count, 3);
        assert!(result.alerts.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_filter_priority() {
        let alerts = vec![
            make_alert(100, AlertPriority::Medium, 0x01),
            make_alert(101, AlertPriority::High, 0x02),
            make_alert(102, AlertPriority::Critical, 0x03),
            make_alert(103, AlertPriority::Medium, 0x04),
        ];
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        // Filter for High or above
        let result = history.query(&AlertQueryParams {
            min_priority: Some(AlertPriority::High),
            ..Default::default()
        });

        assert_eq!(result.total_count, 2);
        for alert in &result.alerts {
            assert!(matches!(
                alert.alert_priority,
                AlertPriority::High | AlertPriority::Critical
            ));
        }

        // Filter for Critical only
        let result = history.query(&AlertQueryParams {
            min_priority: Some(AlertPriority::Critical),
            ..Default::default()
        });
        assert_eq!(result.total_count, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_filter_block_range() {
        let alerts: Vec<SentinelAlert> = (100..110)
            .map(|i| make_alert(i, AlertPriority::High, i as u8))
            .collect();
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            block_range: Some((103, 106)),
            ..Default::default()
        });

        assert_eq!(result.total_count, 4);
        for alert in &result.alerts {
            assert!(alert.block_number >= 103 && alert.block_number <= 106);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_sort_newest() {
        let alerts = vec![
            make_alert(100, AlertPriority::High, 0x01),
            make_alert(105, AlertPriority::High, 0x02),
            make_alert(102, AlertPriority::High, 0x03),
        ];
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            sort_order: SortOrder::Newest,
            ..Default::default()
        });

        assert_eq!(result.alerts[0].block_number, 105);
        assert_eq!(result.alerts[1].block_number, 102);
        assert_eq!(result.alerts[2].block_number, 100);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_sort_oldest() {
        let alerts = vec![
            make_alert(100, AlertPriority::High, 0x01),
            make_alert(105, AlertPriority::High, 0x02),
            make_alert(102, AlertPriority::High, 0x03),
        ];
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        let result = history.query(&AlertQueryParams {
            sort_order: SortOrder::Oldest,
            ..Default::default()
        });

        assert_eq!(result.alerts[0].block_number, 100);
        assert_eq!(result.alerts[1].block_number, 102);
        assert_eq!(result.alerts[2].block_number, 105);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_malformed_lines_skipped() {
        let dir = std::env::temp_dir().join("sentinel_history_tests");
        let _ = std::fs::create_dir_all(&dir);
        let id = TEST_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = dir.join(format!("malformed_{}_{}.jsonl", std::process::id(), id));

        let alert = make_alert(100, AlertPriority::High, 0x01);
        let valid_json = serde_json::to_string(&alert).expect("serialize");

        let mut file = std::fs::File::create(&path).expect("create");
        writeln!(file, "{}", valid_json).expect("write valid");
        writeln!(file, "{{not valid json").expect("write malformed");
        writeln!(file, "").expect("write empty");
        writeln!(file, "{}", valid_json).expect("write valid again");

        let history = AlertHistory::new(path.clone());
        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn history_page_size_clamped() {
        let alerts = vec![make_alert(100, AlertPriority::High, 0x01)];
        let path = write_jsonl(&alerts);
        let history = AlertHistory::new(path.clone());

        // Page size over 100 should be clamped
        let result = history.query(&AlertQueryParams {
            page_size: 500,
            ..Default::default()
        });
        assert_eq!(result.page_size, 100);

        // Page size 0 should be clamped to 1
        let result = history.query(&AlertQueryParams {
            page_size: 0,
            ..Default::default()
        });
        assert_eq!(result.page_size, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(feature = "autopsy")]
    #[test]
    fn history_filter_pattern_type() {
        use crate::autopsy::types::{AttackPattern, DetectedPattern};

        let mut alert_reentrancy = make_alert(100, AlertPriority::Critical, 0x01);
        alert_reentrancy.detected_patterns = vec![DetectedPattern {
            pattern: AttackPattern::Reentrancy {
                target_contract: ethrex_common::Address::zero(),
                reentrant_call_step: 10,
                state_modified_step: 20,
                call_depth_at_entry: 1,
            },
            confidence: 0.9,
            evidence: vec!["test evidence".to_string()],
        }];

        let mut alert_flash = make_alert(101, AlertPriority::High, 0x02);
        alert_flash.detected_patterns = vec![DetectedPattern {
            pattern: AttackPattern::FlashLoan {
                borrow_step: 5,
                borrow_amount: U256::from(1000),
                repay_step: 50,
                repay_amount: U256::from(1000),
                provider: None,
                token: None,
            },
            confidence: 0.8,
            evidence: vec!["flash loan evidence".to_string()],
        }];

        let alert_no_pattern = make_alert(102, AlertPriority::Medium, 0x03);

        let path = write_jsonl(&[alert_reentrancy, alert_flash, alert_no_pattern]);
        let history = AlertHistory::new(path.clone());

        // Filter for Reentrancy
        let result = history.query(&AlertQueryParams {
            pattern_type: Some("Reentrancy".to_string()),
            ..Default::default()
        });
        assert_eq!(result.total_count, 1);
        assert_eq!(result.alerts[0].block_number, 100);

        // Filter for FlashLoan (case-insensitive)
        let result = history.query(&AlertQueryParams {
            pattern_type: Some("flashloan".to_string()),
            ..Default::default()
        });
        assert_eq!(result.total_count, 1);
        assert_eq!(result.alerts[0].block_number, 101);

        let _ = std::fs::remove_file(&path);
    }
}
