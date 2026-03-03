//! Prometheus-compatible metrics collection for the Sentinel pipeline.
//!
//! Uses only `std::sync::atomic::AtomicU64` for lock-free, thread-safe counters.
//! No external crate dependencies.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe counters for the sentinel pipeline.
///
/// All fields are atomic and can be incremented concurrently from any thread.
/// Use [`snapshot()`](SentinelMetrics::snapshot) to read a consistent point-in-time copy.
pub struct SentinelMetrics {
    /// Total number of blocks processed by the worker loop.
    blocks_scanned: AtomicU64,
    /// Total number of transactions scanned by the pre-filter.
    txs_scanned: AtomicU64,
    /// Transactions that passed the pre-filter (flagged as suspicious).
    txs_flagged: AtomicU64,
    /// Alerts emitted after deep analysis confirmed suspicion.
    alerts_emitted: AtomicU64,
    /// Alerts suppressed by the deduplicator.
    alerts_deduplicated: AtomicU64,
    /// Alerts suppressed by the rate limiter.
    alerts_rate_limited: AtomicU64,
    /// Cumulative pre-filter scan time in microseconds.
    prefilter_total_us: AtomicU64,
    /// Cumulative deep analysis time in milliseconds.
    deep_analysis_total_ms: AtomicU64,
    /// Total pending mempool transactions scanned.
    mempool_txs_scanned: AtomicU64,
    /// Mempool transactions flagged as suspicious.
    mempool_txs_flagged: AtomicU64,
    /// Alerts emitted from mempool scanning.
    mempool_alerts_emitted: AtomicU64,
    /// Total pipeline steps executed across all analyses.
    pipeline_steps_executed: AtomicU64,
    /// Pipeline steps that resulted in early dismissal.
    pipeline_steps_dismissed: AtomicU64,
    /// Cumulative pipeline duration in milliseconds.
    pipeline_duration_ms: AtomicU64,
}

impl SentinelMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            blocks_scanned: AtomicU64::new(0),
            txs_scanned: AtomicU64::new(0),
            txs_flagged: AtomicU64::new(0),
            alerts_emitted: AtomicU64::new(0),
            alerts_deduplicated: AtomicU64::new(0),
            alerts_rate_limited: AtomicU64::new(0),
            prefilter_total_us: AtomicU64::new(0),
            deep_analysis_total_ms: AtomicU64::new(0),
            mempool_txs_scanned: AtomicU64::new(0),
            mempool_txs_flagged: AtomicU64::new(0),
            mempool_alerts_emitted: AtomicU64::new(0),
            pipeline_steps_executed: AtomicU64::new(0),
            pipeline_steps_dismissed: AtomicU64::new(0),
            pipeline_duration_ms: AtomicU64::new(0),
        }
    }

    // -- Increment helpers --

    pub fn increment_blocks_scanned(&self) {
        self.blocks_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_txs_scanned(&self, count: u64) {
        self.txs_scanned.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_txs_flagged(&self, count: u64) {
        self.txs_flagged.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_alerts_emitted(&self) {
        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_alerts_deduplicated(&self) {
        self.alerts_deduplicated.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_alerts_rate_limited(&self) {
        self.alerts_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_prefilter_us(&self, us: u64) {
        self.prefilter_total_us.fetch_add(us, Ordering::Relaxed);
    }

    pub fn add_deep_analysis_ms(&self, ms: u64) {
        self.deep_analysis_total_ms.fetch_add(ms, Ordering::Relaxed);
    }

    pub fn increment_mempool_txs_scanned(&self) {
        self.mempool_txs_scanned.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_mempool_txs_flagged(&self) {
        self.mempool_txs_flagged.fetch_add(1, Ordering::Relaxed);
    }

    pub fn increment_mempool_alerts_emitted(&self) {
        self.mempool_alerts_emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_pipeline_steps_executed(&self, count: u64) {
        self.pipeline_steps_executed
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_pipeline_steps_dismissed(&self, count: u64) {
        self.pipeline_steps_dismissed
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_pipeline_duration_ms(&self, ms: u64) {
        self.pipeline_duration_ms.fetch_add(ms, Ordering::Relaxed);
    }

    // -- Snapshot / export --

    /// Read all counters into a non-atomic snapshot.
    ///
    /// Each field is read with `Relaxed` ordering. The snapshot is not globally
    /// consistent across all fields (no single atomic fence), but each individual
    /// counter is accurate at the time of its read.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            blocks_scanned: self.blocks_scanned.load(Ordering::Relaxed),
            txs_scanned: self.txs_scanned.load(Ordering::Relaxed),
            txs_flagged: self.txs_flagged.load(Ordering::Relaxed),
            alerts_emitted: self.alerts_emitted.load(Ordering::Relaxed),
            alerts_deduplicated: self.alerts_deduplicated.load(Ordering::Relaxed),
            alerts_rate_limited: self.alerts_rate_limited.load(Ordering::Relaxed),
            prefilter_total_us: self.prefilter_total_us.load(Ordering::Relaxed),
            deep_analysis_total_ms: self.deep_analysis_total_ms.load(Ordering::Relaxed),
            mempool_txs_scanned: self.mempool_txs_scanned.load(Ordering::Relaxed),
            mempool_txs_flagged: self.mempool_txs_flagged.load(Ordering::Relaxed),
            mempool_alerts_emitted: self.mempool_alerts_emitted.load(Ordering::Relaxed),
            pipeline_steps_executed: self.pipeline_steps_executed.load(Ordering::Relaxed),
            pipeline_steps_dismissed: self.pipeline_steps_dismissed.load(Ordering::Relaxed),
            pipeline_duration_ms: self.pipeline_duration_ms.load(Ordering::Relaxed),
        }
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn to_prometheus_text(&self) -> String {
        self.snapshot().to_prometheus_text()
    }
}

impl Default for SentinelMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// Compile-time assertion: SentinelMetrics must be Send + Sync.
const _: fn() = || {
    fn must_be_send_sync<T: Send + Sync>() {}
    must_be_send_sync::<SentinelMetrics>();
};

/// Non-atomic snapshot of all sentinel metrics at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub blocks_scanned: u64,
    pub txs_scanned: u64,
    pub txs_flagged: u64,
    pub alerts_emitted: u64,
    pub alerts_deduplicated: u64,
    pub alerts_rate_limited: u64,
    pub prefilter_total_us: u64,
    pub deep_analysis_total_ms: u64,
    pub mempool_txs_scanned: u64,
    pub mempool_txs_flagged: u64,
    pub mempool_alerts_emitted: u64,
    pub pipeline_steps_executed: u64,
    pub pipeline_steps_dismissed: u64,
    pub pipeline_duration_ms: u64,
}

impl MetricsSnapshot {
    /// Render as Prometheus text exposition format.
    pub fn to_prometheus_text(&self) -> String {
        let mut out = String::with_capacity(1024);

        write_counter(
            &mut out,
            "sentinel_blocks_scanned",
            "Total blocks scanned by the sentinel",
            self.blocks_scanned,
        );
        write_counter(
            &mut out,
            "sentinel_txs_scanned",
            "Total transactions scanned by the pre-filter",
            self.txs_scanned,
        );
        write_counter(
            &mut out,
            "sentinel_txs_flagged",
            "Transactions flagged as suspicious by the pre-filter",
            self.txs_flagged,
        );
        write_counter(
            &mut out,
            "sentinel_alerts_emitted",
            "Alerts emitted after deep analysis",
            self.alerts_emitted,
        );
        write_counter(
            &mut out,
            "sentinel_alerts_deduplicated",
            "Alerts suppressed by deduplication",
            self.alerts_deduplicated,
        );
        write_counter(
            &mut out,
            "sentinel_alerts_rate_limited",
            "Alerts suppressed by rate limiting",
            self.alerts_rate_limited,
        );
        write_counter(
            &mut out,
            "sentinel_prefilter_total_us",
            "Cumulative pre-filter scan time in microseconds",
            self.prefilter_total_us,
        );
        write_counter(
            &mut out,
            "sentinel_deep_analysis_total_ms",
            "Cumulative deep analysis time in milliseconds",
            self.deep_analysis_total_ms,
        );
        write_counter(
            &mut out,
            "sentinel_mempool_txs_scanned",
            "Total pending mempool transactions scanned",
            self.mempool_txs_scanned,
        );
        write_counter(
            &mut out,
            "sentinel_mempool_txs_flagged",
            "Mempool transactions flagged as suspicious",
            self.mempool_txs_flagged,
        );
        write_counter(
            &mut out,
            "sentinel_mempool_alerts_emitted",
            "Alerts emitted from mempool scanning",
            self.mempool_alerts_emitted,
        );
        write_counter(
            &mut out,
            "sentinel_pipeline_steps_executed",
            "Total pipeline steps executed across all analyses",
            self.pipeline_steps_executed,
        );
        write_counter(
            &mut out,
            "sentinel_pipeline_steps_dismissed",
            "Pipeline steps that resulted in early dismissal",
            self.pipeline_steps_dismissed,
        );
        write_counter(
            &mut out,
            "sentinel_pipeline_duration_ms",
            "Cumulative pipeline duration in milliseconds",
            self.pipeline_duration_ms,
        );

        out
    }
}

impl fmt::Display for MetricsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Sentinel Metrics")?;
        writeln!(f, "  blocks_scanned:       {}", self.blocks_scanned)?;
        writeln!(f, "  txs_scanned:          {}", self.txs_scanned)?;
        writeln!(f, "  txs_flagged:          {}", self.txs_flagged)?;
        writeln!(f, "  alerts_emitted:       {}", self.alerts_emitted)?;
        writeln!(f, "  alerts_deduplicated:  {}", self.alerts_deduplicated)?;
        writeln!(f, "  alerts_rate_limited:  {}", self.alerts_rate_limited)?;
        writeln!(f, "  prefilter_total_us:   {}", self.prefilter_total_us)?;
        writeln!(
            f,
            "  deep_analysis_total_ms: {}",
            self.deep_analysis_total_ms
        )?;
        writeln!(
            f,
            "  mempool_txs_scanned:  {}",
            self.mempool_txs_scanned
        )?;
        writeln!(
            f,
            "  mempool_txs_flagged:  {}",
            self.mempool_txs_flagged
        )?;
        writeln!(
            f,
            "  mempool_alerts_emitted: {}",
            self.mempool_alerts_emitted
        )?;
        writeln!(
            f,
            "  pipeline_steps_executed: {}",
            self.pipeline_steps_executed
        )?;
        writeln!(
            f,
            "  pipeline_steps_dismissed: {}",
            self.pipeline_steps_dismissed
        )?;
        write!(
            f,
            "  pipeline_duration_ms:   {}",
            self.pipeline_duration_ms
        )
    }
}

/// Write a single Prometheus counter metric (HELP + TYPE + value).
fn write_counter(out: &mut String, name: &str, help: &str, value: u64) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(out, "{name} {value}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn sentinel_metrics_zero_state_snapshot() {
        let metrics = SentinelMetrics::new();
        let snap = metrics.snapshot();

        assert_eq!(snap.blocks_scanned, 0);
        assert_eq!(snap.txs_scanned, 0);
        assert_eq!(snap.txs_flagged, 0);
        assert_eq!(snap.alerts_emitted, 0);
        assert_eq!(snap.alerts_deduplicated, 0);
        assert_eq!(snap.alerts_rate_limited, 0);
        assert_eq!(snap.prefilter_total_us, 0);
        assert_eq!(snap.deep_analysis_total_ms, 0);
    }

    #[test]
    fn sentinel_metrics_atomic_increment_correctness() {
        let metrics = SentinelMetrics::new();

        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(10);
        metrics.increment_txs_flagged(3);
        metrics.increment_alerts_emitted();
        metrics.increment_alerts_deduplicated();
        metrics.increment_alerts_rate_limited();
        metrics.add_prefilter_us(500);
        metrics.add_deep_analysis_ms(120);

        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_scanned, 2);
        assert_eq!(snap.txs_scanned, 10);
        assert_eq!(snap.txs_flagged, 3);
        assert_eq!(snap.alerts_emitted, 1);
        assert_eq!(snap.alerts_deduplicated, 1);
        assert_eq!(snap.alerts_rate_limited, 1);
        assert_eq!(snap.prefilter_total_us, 500);
        assert_eq!(snap.deep_analysis_total_ms, 120);
    }

    #[test]
    fn sentinel_metrics_snapshot_captures_current_values() {
        let metrics = SentinelMetrics::new();

        metrics.increment_blocks_scanned();
        let snap1 = metrics.snapshot();

        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        let snap2 = metrics.snapshot();

        assert_eq!(snap1.blocks_scanned, 1);
        assert_eq!(snap2.blocks_scanned, 3);
        // snap1 is a frozen copy, not affected by later increments
        assert_eq!(snap1.blocks_scanned, 1);
    }

    #[test]
    fn sentinel_metrics_prometheus_text_format_validity() {
        let metrics = SentinelMetrics::new();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(42);
        metrics.increment_alerts_emitted();
        metrics.add_prefilter_us(1234);

        let text = metrics.to_prometheus_text();

        // Verify HELP and TYPE annotations
        assert!(text.contains("# HELP sentinel_blocks_scanned"));
        assert!(text.contains("# TYPE sentinel_blocks_scanned counter"));
        assert!(text.contains("sentinel_blocks_scanned 1"));

        assert!(text.contains("# HELP sentinel_txs_scanned"));
        assert!(text.contains("# TYPE sentinel_txs_scanned counter"));
        assert!(text.contains("sentinel_txs_scanned 42"));

        assert!(text.contains("sentinel_alerts_emitted 1"));
        assert!(text.contains("sentinel_prefilter_total_us 1234"));

        // Zero values should still be present
        assert!(text.contains("sentinel_txs_flagged 0"));
        assert!(text.contains("sentinel_alerts_deduplicated 0"));
        assert!(text.contains("sentinel_alerts_rate_limited 0"));
        assert!(text.contains("sentinel_deep_analysis_total_ms 0"));

        // Each metric should have exactly 3 lines: HELP, TYPE, value
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 42); // 14 metrics * 3 lines each
    }

    #[test]
    fn sentinel_metrics_display_format() {
        let metrics = SentinelMetrics::new();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(5);

        let snap = metrics.snapshot();
        let display = format!("{snap}");

        assert!(display.contains("Sentinel Metrics"));
        assert!(display.contains("blocks_scanned:       1"));
        assert!(display.contains("txs_scanned:          5"));
    }

    #[test]
    fn sentinel_metrics_concurrent_increment_safety() {
        let metrics = Arc::new(SentinelMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..8 {
            let m = metrics.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.increment_blocks_scanned();
                    m.increment_txs_scanned(1);
                    m.increment_txs_flagged(1);
                    m.increment_alerts_emitted();
                    m.add_prefilter_us(1);
                    m.add_deep_analysis_ms(1);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_scanned, 8000);
        assert_eq!(snap.txs_scanned, 8000);
        assert_eq!(snap.txs_flagged, 8000);
        assert_eq!(snap.alerts_emitted, 8000);
        assert_eq!(snap.prefilter_total_us, 8000);
        assert_eq!(snap.deep_analysis_total_ms, 8000);
    }

    #[test]
    fn sentinel_metrics_default_is_zero() {
        let metrics = SentinelMetrics::default();
        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_scanned, 0);
        assert_eq!(snap.txs_scanned, 0);
    }

    #[test]
    fn sentinel_metrics_snapshot_equality() {
        let m1 = SentinelMetrics::new();
        let m2 = SentinelMetrics::new();

        assert_eq!(m1.snapshot(), m2.snapshot());

        m1.increment_blocks_scanned();
        assert_ne!(m1.snapshot(), m2.snapshot());
    }

    #[test]
    fn sentinel_metrics_additive_accumulation() {
        let metrics = SentinelMetrics::new();

        metrics.add_prefilter_us(100);
        metrics.add_prefilter_us(200);
        metrics.add_prefilter_us(300);

        metrics.add_deep_analysis_ms(50);
        metrics.add_deep_analysis_ms(75);

        let snap = metrics.snapshot();
        assert_eq!(snap.prefilter_total_us, 600);
        assert_eq!(snap.deep_analysis_total_ms, 125);
    }
}
