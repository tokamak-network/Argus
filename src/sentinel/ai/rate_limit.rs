//! Rate limiting for AI API calls: sliding-window hourly tracker and per-block concurrency.

use std::time::{Duration, Instant};

// ── Hourly Rate Tracker ────────────────────────────────────────────────────

/// Tracks request timestamps within a sliding 1-hour window for rate limiting.
pub struct HourlyRateTracker {
    /// Timestamps of requests in the current window.
    timestamps: Vec<Instant>,
    /// Maximum requests per hour.
    limit: u32,
}

impl HourlyRateTracker {
    /// Create a new tracker with the given hourly limit.
    pub fn new(limit: u32) -> Self {
        Self {
            timestamps: Vec::new(),
            limit,
        }
    }

    /// Check if a new request is allowed under the hourly rate limit.
    pub fn is_allowed(&self) -> bool {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        let active_count = self.timestamps.iter().filter(|t| **t > cutoff).count();
        (active_count as u32) < self.limit
    }

    /// Record a new request timestamp.
    /// Returns a new tracker with the timestamp added and old entries pruned.
    pub fn with_request_recorded(&self) -> Self {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(3600);
        let mut timestamps: Vec<Instant> = self
            .timestamps
            .iter()
            .filter(|t| **t > cutoff)
            .copied()
            .collect();
        timestamps.push(now);
        Self {
            timestamps,
            limit: self.limit,
        }
    }

    /// Number of requests in the current 1-hour window.
    pub fn current_count(&self) -> u32 {
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.timestamps.iter().filter(|t| **t > cutoff).count() as u32
    }
}

// ── Concurrent Block Tracker ───────────────────────────────────────────────

/// Tracks active AI requests per block for concurrency limiting.
pub struct BlockConcurrencyTracker {
    /// Currently active block number and count.
    active_block: Option<u64>,
    active_count: u8,
    /// Maximum concurrent requests per block.
    limit: u8,
}

impl BlockConcurrencyTracker {
    pub fn new(limit: u8) -> Self {
        Self {
            active_block: None,
            active_count: 0,
            limit,
        }
    }

    /// Check if a new request for the given block is allowed.
    pub fn is_allowed(&self, block_number: u64) -> bool {
        match self.active_block {
            Some(b) if b == block_number => self.active_count < self.limit,
            _ => true, // New block or no active block — always allowed
        }
    }

    /// Record that a request started for the given block.
    pub fn acquire(&mut self, block_number: u64) {
        match self.active_block {
            Some(b) if b == block_number => {
                self.active_count += 1;
            }
            _ => {
                self.active_block = Some(block_number);
                self.active_count = 1;
            }
        }
    }

    /// Record that a request finished for the given block.
    pub fn release(&mut self, block_number: u64) {
        if self.active_block == Some(block_number) && self.active_count > 0 {
            self.active_count -= 1;
            if self.active_count == 0 {
                self.active_block = None;
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── HourlyRateTracker ───────────────────────────────────────────────

    #[test]
    fn hourly_tracker_allows_within_limit() {
        let tracker = HourlyRateTracker::new(100);
        assert!(tracker.is_allowed());
        assert_eq!(tracker.current_count(), 0);
    }

    #[test]
    fn hourly_tracker_blocks_at_limit() {
        let mut tracker = HourlyRateTracker::new(3);
        for _ in 0..3 {
            tracker = tracker.with_request_recorded();
        }
        assert!(!tracker.is_allowed());
        assert_eq!(tracker.current_count(), 3);
    }

    #[test]
    fn hourly_tracker_records_request() {
        let tracker = HourlyRateTracker::new(100);
        let updated = tracker.with_request_recorded();
        assert_eq!(updated.current_count(), 1);
        assert!(updated.is_allowed());
    }

    // ── BlockConcurrencyTracker ─────────────────────────────────────────

    #[test]
    fn block_concurrency_allows_new_block() {
        let tracker = BlockConcurrencyTracker::new(3);
        assert!(tracker.is_allowed(100));
    }

    #[test]
    fn block_concurrency_tracks_same_block() {
        let mut tracker = BlockConcurrencyTracker::new(2);
        tracker.acquire(100);
        assert!(tracker.is_allowed(100));
        tracker.acquire(100);
        assert!(!tracker.is_allowed(100));
    }

    #[test]
    fn block_concurrency_release_allows_more() {
        let mut tracker = BlockConcurrencyTracker::new(1);
        tracker.acquire(100);
        assert!(!tracker.is_allowed(100));
        tracker.release(100);
        assert!(tracker.is_allowed(100));
    }

    #[test]
    fn block_concurrency_new_block_resets() {
        let mut tracker = BlockConcurrencyTracker::new(1);
        tracker.acquire(100);
        assert!(!tracker.is_allowed(100));
        assert!(tracker.is_allowed(101));
    }
}
