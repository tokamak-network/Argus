//! Observability metrics for autopsy analysis.
//!
//! Tracks RPC calls, cache hits, timing, and report size.
//! Printed to stderr at end of analysis.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Metrics collected during an autopsy analysis run.
pub struct AutopsyMetrics {
    rpc_calls: AtomicU64,
    cache_hits: AtomicU64,
    rpc_latency_total_ms: AtomicU64,
    rpc_latency_min_ms: AtomicU64,
    rpc_latency_max_ms: AtomicU64,
    start_time: Instant,
}

impl AutopsyMetrics {
    pub fn new() -> Self {
        Self {
            rpc_calls: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            rpc_latency_total_ms: AtomicU64::new(0),
            rpc_latency_min_ms: AtomicU64::new(u64::MAX),
            rpc_latency_max_ms: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    /// Record an RPC call with its latency.
    pub fn record_rpc_call(&self, latency_ms: u64) {
        self.rpc_calls.fetch_add(1, Ordering::Relaxed);
        self.rpc_latency_total_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.rpc_latency_min_ms
            .fetch_min(latency_ms, Ordering::Relaxed);
        self.rpc_latency_max_ms
            .fetch_max(latency_ms, Ordering::Relaxed);
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the number of RPC calls made.
    pub fn rpc_call_count(&self) -> u64 {
        self.rpc_calls.load(Ordering::Relaxed)
    }

    /// Get the number of cache hits.
    pub fn cache_hit_count(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Compute cache hit rate as a percentage.
    pub fn hit_rate_percent(&self) -> f64 {
        let calls = self.rpc_call_count();
        let hits = self.cache_hit_count();
        let total = calls + hits;
        if total == 0 {
            return 0.0;
        }
        (hits as f64 / total as f64) * 100.0
    }

    /// Format metrics for display (printed to stderr).
    pub fn display(
        &self,
        trace_steps: usize,
        classification_ms: u64,
        report_size_bytes: usize,
    ) -> String {
        let calls = self.rpc_call_count();
        let hits = self.cache_hit_count();
        let hit_rate = self.hit_rate_percent();
        let total_ms = self.start_time.elapsed().as_millis();

        let latency_min = self.rpc_latency_min_ms.load(Ordering::Relaxed);
        let latency_max = self.rpc_latency_max_ms.load(Ordering::Relaxed);
        let latency_avg = if calls > 0 {
            self.rpc_latency_total_ms.load(Ordering::Relaxed) / calls
        } else {
            0
        };

        let min_str = if latency_min == u64::MAX {
            "N/A".to_string()
        } else {
            format!("{latency_min}ms")
        };

        let report_kb = report_size_bytes as f64 / 1024.0;

        format!(
            "[autopsy] RPC calls: {calls} (cache hits: {hits}, hit rate: {hit_rate:.1}%)\n\
             [autopsy] RPC latency: min={min_str} avg={latency_avg}ms max={latency_max}ms\n\
             [autopsy] Trace steps: {trace_steps}, classification: {classification_ms}ms\n\
             [autopsy] Report: {report_kb:.1}KB, total time: {total_ms}ms"
        )
    }
}

impl Default for AutopsyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_counter_increments() {
        let m = AutopsyMetrics::new();
        assert_eq!(m.rpc_call_count(), 0);
        assert_eq!(m.cache_hit_count(), 0);

        m.record_rpc_call(50);
        m.record_rpc_call(100);
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_cache_hit();

        assert_eq!(m.rpc_call_count(), 2);
        assert_eq!(m.cache_hit_count(), 3);
    }

    #[test]
    fn test_display_formatting() {
        let m = AutopsyMetrics::new();
        m.record_rpc_call(10);
        m.record_rpc_call(50);
        m.record_cache_hit();

        let output = m.display(1000, 23, 3200);
        assert!(output.contains("[autopsy] RPC calls: 2"));
        assert!(output.contains("cache hits: 1"));
        assert!(output.contains("Trace steps: 1000"));
        assert!(output.contains("classification: 23ms"));
    }

    #[test]
    fn test_cache_hit_rate_calculation() {
        let m = AutopsyMetrics::new();

        // No data → 0%
        assert!((m.hit_rate_percent()).abs() < 0.01);

        // 3 hits, 1 call → 3/(3+1) = 75%
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_cache_hit();
        m.record_rpc_call(10);

        assert!((m.hit_rate_percent() - 75.0).abs() < 0.1);
    }
}
