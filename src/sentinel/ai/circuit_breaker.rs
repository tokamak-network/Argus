//! Circuit breaker that disables AI calls after consecutive failures.
//!
//! Like a fuse box: after too many short circuits (API failures), the fuse blows
//! and power is cut for a cooldown period. After the cooldown, the circuit
//! resets and tries again.

use std::time::{Duration, Instant};

/// Circuit breaker for AI API failure protection.
pub struct CircuitBreaker {
    /// Number of consecutive failures.
    consecutive_failures: u32,
    /// Threshold before tripping.
    threshold: u32,
    /// When the circuit was tripped (None = circuit is closed/healthy).
    tripped_at: Option<Instant>,
    /// How long to stay open before auto-reset.
    cooldown: Duration,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            consecutive_failures: 0,
            threshold,
            tripped_at: None,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Returns true if the circuit breaker is open (tripped) and cooldown hasn't elapsed.
    pub fn is_open(&self) -> bool {
        match self.tripped_at {
            Some(tripped) => tripped.elapsed() < self.cooldown,
            None => false,
        }
    }

    /// Record a successful API call. Resets consecutive failure count and closes circuit.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.tripped_at = None;
    }

    /// Record a failed API call. If threshold is reached, trip the breaker.
    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= self.threshold {
            self.tripped_at = Some(Instant::now());
        }
    }

    /// Number of consecutive failures so far.
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new(5, 600);
        assert!(!cb.is_open());
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn circuit_breaker_trips_at_threshold() {
        let mut cb = CircuitBreaker::new(3, 600);
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.is_open());
        cb.record_failure();
        assert!(cb.is_open());
        assert_eq!(cb.consecutive_failures(), 3);
    }

    #[test]
    fn circuit_breaker_success_resets() {
        let mut cb = CircuitBreaker::new(3, 600);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.consecutive_failures(), 0);
        assert!(!cb.is_open());
    }

    #[test]
    fn circuit_breaker_cooldown_resets() {
        let mut cb = CircuitBreaker::new(1, 0); // 0-second cooldown
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        assert!(!cb.is_open());
    }
}
