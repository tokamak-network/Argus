//! Auto-pause circuit breaker for the sentinel system.
//!
//! `AutoPauseHandler` implements `AlertHandler` and pauses block processing
//! via a shared `PauseController` when a sufficiently severe alert is detected.

use std::sync::Arc;

use ethrex_blockchain::PauseController;

use super::config::AutoPauseConfig;
use super::service::AlertHandler;
use super::types::{AlertPriority, SentinelAlert};

/// Alert handler that pauses block processing on critical alerts.
///
/// Acts as a circuit breaker: when an alert meets both the confidence threshold
/// and priority threshold, the handler calls `PauseController::pause()` to halt
/// block ingestion until an operator (or auto-resume timer) resumes it.
pub struct AutoPauseHandler {
    controller: Arc<PauseController>,
    confidence_threshold: f64,
    priority_threshold: AlertPriority,
}

impl AutoPauseHandler {
    /// Create a new handler from config and a shared pause controller.
    pub fn new(controller: Arc<PauseController>, config: &AutoPauseConfig) -> Self {
        let priority_threshold = match config.priority_threshold.as_str() {
            "Medium" => AlertPriority::Medium,
            "High" => AlertPriority::High,
            _ => AlertPriority::Critical,
        };

        Self {
            controller,
            confidence_threshold: config.confidence_threshold,
            priority_threshold,
        }
    }

    /// Create with explicit thresholds (useful for testing).
    pub fn with_thresholds(
        controller: Arc<PauseController>,
        confidence_threshold: f64,
        priority_threshold: AlertPriority,
    ) -> Self {
        Self {
            controller,
            confidence_threshold,
            priority_threshold,
        }
    }

    /// Access the underlying pause controller.
    pub fn controller(&self) -> &Arc<PauseController> {
        &self.controller
    }
}

impl AlertHandler for AutoPauseHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        if alert.alert_priority >= self.priority_threshold
            && alert.suspicion_score >= self.confidence_threshold
        {
            eprintln!(
                "[SENTINEL AUTO-PAUSE] Critical attack detected: tx={:?}, score={:.2}, priority={:?}",
                alert.tx_hash, alert.suspicion_score, alert.alert_priority
            );
            self.controller.pause();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{H256, U256};

    fn make_alert(priority: AlertPriority, score: f64) -> SentinelAlert {
        SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: priority,
            suspicion_reasons: vec![],
            suspicion_score: score,
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: "test alert".to_string(),
            total_steps: 0,
            feature_vector: None,
        }
    }

    #[test]
    fn critical_alert_high_confidence_triggers_pause() {
        let pc = Arc::new(PauseController::new(Some(300)));
        let handler = AutoPauseHandler::with_thresholds(
            Arc::clone(&pc),
            0.8,
            AlertPriority::Critical,
        );

        assert!(!pc.is_paused());
        handler.on_alert(make_alert(AlertPriority::Critical, 0.9));
        assert!(pc.is_paused());
        pc.resume();
    }

    #[test]
    fn high_priority_does_not_trigger_pause() {
        let pc = Arc::new(PauseController::new(Some(300)));
        let handler = AutoPauseHandler::with_thresholds(
            Arc::clone(&pc),
            0.8,
            AlertPriority::Critical,
        );

        handler.on_alert(make_alert(AlertPriority::High, 0.9));
        assert!(!pc.is_paused(), "High priority should not trigger pause when threshold is Critical");
    }

    #[test]
    fn critical_alert_low_confidence_does_not_trigger_pause() {
        let pc = Arc::new(PauseController::new(Some(300)));
        let handler = AutoPauseHandler::with_thresholds(
            Arc::clone(&pc),
            0.8,
            AlertPriority::Critical,
        );

        handler.on_alert(make_alert(AlertPriority::Critical, 0.5));
        assert!(!pc.is_paused(), "Low confidence should not trigger pause");
    }
}
