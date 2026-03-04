//! HTTP server exposing `/metrics` (Prometheus) and `/health` (JSON) endpoints.

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde_json::json;

use super::metrics::SentinelMetrics;

struct MetricsState {
    metrics: Arc<SentinelMetrics>,
    start_time: Instant,
}

async fn handle_metrics(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    let body = state.metrics.to_prometheus_text();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, body)
}

async fn handle_health(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    let snap = state.metrics.snapshot();
    let uptime_secs = state.start_time.elapsed().as_secs();
    let body = json!({
        "status": "running",
        "blocks_scanned": snap.blocks_scanned,
        "txs_scanned": snap.txs_scanned,
        "alerts_emitted": snap.alerts_emitted,
        "uptime_secs": uptime_secs,
    });
    axum::Json(body)
}

/// Start the HTTP metrics server on the given port.
///
/// Serves:
/// - `GET /metrics` — Prometheus text exposition format
/// - `GET /health`  — JSON status snapshot
///
/// Runs until the process exits or the listener is closed.
pub async fn start_metrics_server(
    metrics: Arc<SentinelMetrics>,
    port: u16,
    start_time: Instant,
) -> Result<(), String> {
    let state = Arc::new(MetricsState {
        metrics,
        start_time,
    });

    let app = Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/health", get(handle_health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| format!("failed to bind port {port}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("metrics server error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    async fn spawn_server(port: u16) -> Arc<SentinelMetrics> {
        let metrics = Arc::new(SentinelMetrics::new());
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            start_metrics_server(metrics_clone, port, Instant::now())
                .await
                .ok();
        });
        // Give the server a moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        metrics
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let port = 19100u16;
        let metrics = spawn_server(port).await;
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(42);
        metrics.increment_alerts_emitted();

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/health"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["status"], "running");
        assert_eq!(body["blocks_scanned"], 1);
        assert_eq!(body["txs_scanned"], 42);
        assert_eq!(body["alerts_emitted"], 1);
        assert!(body["uptime_secs"].as_u64().is_some());
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let port = 19101u16;
        let metrics = spawn_server(port).await;
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(7);

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/metrics"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let body = resp.text().await.expect("no body");
        assert!(
            body.contains("sentinel_blocks_scanned"),
            "missing sentinel_blocks_scanned in: {body}"
        );
        assert!(
            body.contains("# TYPE sentinel_blocks_scanned counter"),
            "missing TYPE line"
        );
        assert!(body.contains("sentinel_blocks_scanned 1"));
        assert!(body.contains("sentinel_txs_scanned 7"));
    }

    #[tokio::test]
    async fn test_metrics_content_type() {
        let port = 19102u16;
        spawn_server(port).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/metrics"))
            .await
            .expect("request failed");

        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/plain"), "unexpected content-type: {ct}");
        assert!(ct.contains("version=0.0.4"), "missing version in: {ct}");
    }
}
