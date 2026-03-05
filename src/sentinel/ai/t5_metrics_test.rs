//! T4: AI metrics integration tests.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::sentinel::metrics::SentinelMetrics;

    /// AI metrics appear in Prometheus text with ai_agent feature.
    #[test]
    fn metrics_ai_fields_in_prometheus_output() {
        let metrics = SentinelMetrics::new();

        metrics.increment_ai_screening_requests();
        metrics.increment_ai_screening_requests();
        metrics.increment_ai_escalation_requests();
        metrics.add_ai_request_latency_ms(150);
        metrics.add_ai_cost_usd(0.005);
        metrics.increment_ai_attacks_detected();
        metrics.increment_ai_escalations_total();
        metrics.set_ai_circuit_breaker_open(false);

        let text = metrics.to_prometheus_text();

        assert!(
            text.contains("sentinel_ai_requests_total"),
            "should contain ai_requests_total"
        );
        assert!(
            text.contains("sentinel_ai_requests_total{model=\"screening\"} 2"),
            "screening requests should be 2"
        );
        assert!(
            text.contains("sentinel_ai_requests_total{model=\"escalation\"} 1"),
            "escalation requests should be 1"
        );
        assert!(
            text.contains("sentinel_ai_request_latency_ms_sum 150"),
            "latency sum should be 150"
        );
        assert!(
            text.contains("sentinel_ai_request_latency_ms_count 1"),
            "latency count should be 1"
        );
        assert!(
            text.contains("sentinel_ai_cost_usd_total"),
            "should contain ai_cost"
        );
        assert!(
            text.contains("sentinel_ai_attacks_detected 1"),
            "attacks detected should be 1"
        );
        assert!(
            text.contains("sentinel_ai_escalations_total 1"),
            "escalations should be 1"
        );
        assert!(
            text.contains("sentinel_ai_circuit_breaker_open 0"),
            "circuit breaker should be closed (0)"
        );
    }

    /// AI metrics at zero state are still present in Prometheus output.
    #[test]
    fn metrics_ai_fields_zero_state() {
        let metrics = SentinelMetrics::new();
        let text = metrics.to_prometheus_text();

        assert!(text.contains("sentinel_ai_requests_total{model=\"screening\"} 0"));
        assert!(text.contains("sentinel_ai_requests_total{model=\"escalation\"} 0"));
        assert!(text.contains("sentinel_ai_request_latency_ms_sum 0"));
        assert!(text.contains("sentinel_ai_request_latency_ms_count 0"));
        assert!(text.contains("sentinel_ai_attacks_detected 0"));
        assert!(text.contains("sentinel_ai_escalations_total 0"));
        assert!(text.contains("sentinel_ai_circuit_breaker_open 0"));
    }

    /// AI cost conversion from f64 to micro-USD is accurate.
    #[test]
    fn metrics_ai_cost_micro_usd_conversion() {
        let metrics = SentinelMetrics::new();

        metrics.add_ai_cost_usd(0.005);
        metrics.add_ai_cost_usd(0.015);

        let text = metrics.to_prometheus_text();
        assert!(
            text.contains("sentinel_ai_cost_usd_total 0.020000"),
            "cost should be $0.020000, got: {}",
            text.lines()
                .find(|l| l.contains("sentinel_ai_cost_usd_total"))
                .unwrap_or("NOT FOUND")
        );
    }

    /// Circuit breaker gauge toggles correctly.
    #[test]
    fn metrics_ai_circuit_breaker_toggle() {
        let metrics = SentinelMetrics::new();

        metrics.set_ai_circuit_breaker_open(true);
        let text1 = metrics.to_prometheus_text();
        assert!(text1.contains("sentinel_ai_circuit_breaker_open 1"));

        metrics.set_ai_circuit_breaker_open(false);
        let text2 = metrics.to_prometheus_text();
        assert!(text2.contains("sentinel_ai_circuit_breaker_open 0"));
    }

    /// AI metrics have correct Prometheus TYPE annotations.
    #[test]
    fn metrics_ai_type_annotations() {
        let metrics = SentinelMetrics::new();
        let text = metrics.to_prometheus_text();

        assert!(text.contains("# TYPE sentinel_ai_requests_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_request_latency_ms summary"));
        assert!(text.contains("# TYPE sentinel_ai_cost_usd_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_attacks_detected counter"));
        assert!(text.contains("# TYPE sentinel_ai_escalations_total counter"));
        assert!(text.contains("# TYPE sentinel_ai_circuit_breaker_open gauge"));
    }

    /// Snapshot includes AI metrics.
    #[test]
    fn metrics_snapshot_includes_ai_fields() {
        let metrics = SentinelMetrics::new();
        metrics.increment_ai_screening_requests();
        metrics.increment_ai_escalation_requests();
        metrics.add_ai_request_latency_ms(200);
        metrics.add_ai_cost_usd(0.01);
        metrics.increment_ai_attacks_detected();

        let snap = metrics.snapshot();
        assert_eq!(snap.ai_screening_requests, 1);
        assert_eq!(snap.ai_escalation_requests, 1);
        assert_eq!(snap.ai_request_latency_total_ms, 200);
        assert_eq!(snap.ai_request_latency_count, 1);
        assert_eq!(snap.ai_cost_micro_usd_total, 10_000);
        assert_eq!(snap.ai_attacks_detected, 1);
    }

    /// Concurrent AI metric increments are safe.
    #[test]
    fn metrics_ai_concurrent_safety() {
        let metrics = Arc::new(SentinelMetrics::new());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let m = metrics.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..500 {
                    m.increment_ai_screening_requests();
                    m.increment_ai_escalation_requests();
                    m.add_ai_request_latency_ms(1);
                    m.add_ai_cost_usd(0.001);
                    m.increment_ai_attacks_detected();
                    m.increment_ai_escalations_total();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should not panic");
        }

        let snap = metrics.snapshot();
        assert_eq!(snap.ai_screening_requests, 2000);
        assert_eq!(snap.ai_escalation_requests, 2000);
        assert_eq!(snap.ai_request_latency_total_ms, 2000);
        assert_eq!(snap.ai_request_latency_count, 2000);
        assert_eq!(snap.ai_attacks_detected, 2000);
        assert_eq!(snap.ai_escalations_total, 2000);
    }
}
