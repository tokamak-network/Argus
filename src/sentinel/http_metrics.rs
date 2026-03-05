//! HTTP server exposing Prometheus metrics, health checks, and JSON API endpoints.
//!
//! Endpoints:
//! - `GET /metrics`           — Prometheus text exposition format
//! - `GET /health`            — JSON status snapshot
//! - `GET /sentinel/metrics`  — JSON metrics snapshot (for dashboard)
//! - `GET /sentinel/history`  — JSON paginated alert history

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::cors::CorsLayer;

use super::history::{AlertHistory, AlertQueryParams, AlertQueryResult, SortOrder};
use super::metrics::SentinelMetrics;
use super::types::AlertPriority;
use super::ws_broadcaster::WsAlertBroadcaster;

// ---------------------------------------------------------------------------
// Shared server state
// ---------------------------------------------------------------------------

struct AppState {
    metrics: Arc<SentinelMetrics>,
    start_time: Instant,
    history: AlertHistory,
    #[allow(dead_code)]
    broadcaster: Arc<WsAlertBroadcaster>,
}

// ---------------------------------------------------------------------------
// Existing handlers (unchanged behavior)
// ---------------------------------------------------------------------------

async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let body = state.metrics.to_prometheus_text();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, body)
}

async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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

// ---------------------------------------------------------------------------
// New JSON API handlers
// ---------------------------------------------------------------------------

/// `GET /sentinel/metrics` — returns the dashboard-facing metrics as JSON.
///
/// Returns only the 4 fields the dashboard TS type expects:
/// `{ blocks_scanned, txs_scanned, txs_flagged, alerts_emitted }`.
async fn handle_sentinel_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.metrics.snapshot();
    axum::Json(json!({
        "blocks_scanned": snap.blocks_scanned,
        "txs_scanned": snap.txs_scanned,
        "txs_flagged": snap.txs_flagged,
        "alerts_emitted": snap.alerts_emitted,
    }))
}

/// Query parameters for `GET /sentinel/history`.
///
/// Uses flat `block_from`/`block_to` fields (per PRD) instead of a tuple.
#[derive(Debug, Deserialize)]
struct HistoryQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    priority: Option<String>,
    block_from: Option<u64>,
    block_to: Option<u64>,
    pattern_type: Option<String>,
}

impl HistoryQuery {
    /// Convert HTTP query params into the domain `AlertQueryParams`.
    fn into_alert_query_params(self) -> AlertQueryParams {
        let page = self.page.unwrap_or(1);
        let page_size = self.page_size.unwrap_or(20);

        let min_priority = self.priority.and_then(|s| match s.to_lowercase().as_str() {
            "medium" => Some(AlertPriority::Medium),
            "high" => Some(AlertPriority::High),
            "critical" => Some(AlertPriority::Critical),
            _ => None,
        });

        let block_range = match (self.block_from, self.block_to) {
            (Some(from), Some(to)) => Some((from, to)),
            (Some(from), None) => Some((from, u64::MAX)),
            (None, Some(to)) => Some((0, to)),
            (None, None) => None,
        };

        AlertQueryParams {
            page,
            page_size,
            min_priority,
            block_range,
            pattern_type: self.pattern_type,
            sort_order: SortOrder::Newest,
        }
    }
}

/// `GET /sentinel/history` — paginated, filterable alert history.
///
/// Remaps the response to match the dashboard TS types:
/// - `total_count` -> `total`
/// - `suspicion_reasons`: externally-tagged -> `{ type, details }`
async fn handle_sentinel_history(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HistoryQuery>,
) -> impl IntoResponse {
    let query_params = params.into_alert_query_params();
    let result: AlertQueryResult = state.history.query(&query_params);

    let alerts: Vec<serde_json::Value> = result
        .alerts
        .iter()
        .map(|alert| {
            let mut v = serde_json::to_value(alert).unwrap_or_default();
            if let Some(reasons) = v.get("suspicion_reasons").cloned() {
                let remapped = remap_suspicion_reasons(&reasons);
                if let Some(obj) = v.as_object_mut() {
                    obj.insert("suspicion_reasons".to_string(), remapped);
                }
            }
            v
        })
        .collect();

    axum::Json(json!({
        "alerts": alerts,
        "total": result.total_count,
        "page": result.page,
        "page_size": result.page_size,
    }))
}

/// Transform Rust's externally-tagged enum serialization into `{ type, details }`.
///
/// Rust default: `{"FlashLoanSignature": {"provider_address": "0x..."}}`
/// Dashboard expects: `{"type": "FlashLoanSignature", "details": {"provider_address": "0x..."}}`
fn remap_suspicion_reasons(reasons: &serde_json::Value) -> serde_json::Value {
    let arr = match reasons.as_array() {
        Some(a) => a,
        None => return serde_json::Value::Array(vec![]),
    };

    let remapped: Vec<serde_json::Value> = arr
        .iter()
        .map(|reason| {
            if let Some(obj) = reason.as_object() {
                // Externally-tagged: single key = variant name
                if obj.len() == 1
                    && let Some((variant_name, details)) = obj.iter().next()
                {
                    return json!({
                        "type": variant_name,
                        "details": details,
                    });
                }
            }
            // Unit variant or string — wrap as type-only
            if let Some(s) = reason.as_str() {
                return json!({ "type": s });
            }
            reason.clone()
        })
        .collect();

    serde_json::Value::Array(remapped)
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the HTTP server on the given port.
///
/// Serves:
/// - `GET /metrics`           — Prometheus text exposition format
/// - `GET /health`            — JSON status snapshot
/// - `GET /sentinel/metrics`  — JSON metrics snapshot (for dashboard)
/// - `GET /sentinel/history`  — Paginated alert history JSON
///
/// CORS is enabled for all origins to support local development with
/// a separate frontend dev server.
///
/// Runs until the process exits or the listener is closed.
pub async fn start_metrics_server(
    metrics: Arc<SentinelMetrics>,
    port: u16,
    start_time: Instant,
    alert_file: Option<PathBuf>,
    broadcaster: Option<Arc<WsAlertBroadcaster>>,
) -> Result<(), String> {
    let history_path = alert_file.unwrap_or_else(|| PathBuf::from("sentinel_alerts.jsonl"));
    let broadcaster = broadcaster.unwrap_or_else(|| Arc::new(WsAlertBroadcaster::new()));

    let state = Arc::new(AppState {
        metrics,
        start_time,
        history: AlertHistory::new(history_path),
        broadcaster,
    });

    let app = Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/health", get(handle_health))
        .route("/sentinel/metrics", get(handle_sentinel_metrics))
        .route("/sentinel/history", get(handle_sentinel_history))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .map_err(|e| format!("failed to bind port {port}: {e}"))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| format!("metrics server error: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::types::SentinelAlert;
    use ethrex_common::{H256, U256};
    use std::io::Write;
    use std::sync::Arc;
    use std::time::Instant;

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
            whitelist_matches: 0,
            summary: format!("Test alert at block {block_number}"),
            total_steps: 100,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        }
    }

    static TEST_PORT_COUNTER: std::sync::atomic::AtomicU16 =
        std::sync::atomic::AtomicU16::new(19200);

    static TEST_FILE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn next_port() -> u16 {
        TEST_PORT_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    fn write_jsonl(alerts: &[SentinelAlert]) -> PathBuf {
        let dir = std::env::temp_dir().join("http_metrics_tests");
        let _ = std::fs::create_dir_all(&dir);
        let id = std::process::id();
        let counter = TEST_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = dir.join(format!("alerts_{id}_{counter}.jsonl"));
        let mut file = std::fs::File::create(&path).expect("create test file");
        for alert in alerts {
            let json = serde_json::to_string(alert).expect("serialize alert");
            writeln!(file, "{json}").expect("write line");
        }
        path
    }

    async fn spawn_server_with_alerts(port: u16, alerts: &[SentinelAlert]) -> Arc<SentinelMetrics> {
        let alert_file = write_jsonl(alerts);
        let metrics = Arc::new(SentinelMetrics::new());
        let metrics_clone = metrics.clone();
        tokio::spawn(async move {
            start_metrics_server(metrics_clone, port, Instant::now(), Some(alert_file), None)
                .await
                .ok();
        });
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        metrics
    }

    async fn spawn_server(port: u16) -> Arc<SentinelMetrics> {
        spawn_server_with_alerts(port, &[]).await
    }

    // -- Existing endpoint tests (unchanged behavior) --

    #[tokio::test]
    async fn test_health_endpoint() {
        let port = next_port();
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
        let port = next_port();
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
        let port = next_port();
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

    // -- New JSON API tests --

    #[tokio::test]
    async fn test_sentinel_metrics_endpoint() {
        let port = next_port();
        let metrics = spawn_server(port).await;
        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(100);
        metrics.increment_txs_flagged(5);
        metrics.increment_alerts_emitted();
        metrics.add_prefilter_us(1234);
        metrics.add_deep_analysis_ms(500);

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/sentinel/metrics"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/json"),
            "expected JSON content-type, got: {ct}"
        );

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["blocks_scanned"], 2);
        assert_eq!(body["txs_scanned"], 100);
        assert_eq!(body["txs_flagged"], 5);
        assert_eq!(body["alerts_emitted"], 1);
        // Only 4 fields exposed to dashboard — extra fields must NOT appear
        assert!(
            body.get("prefilter_total_us").is_none(),
            "prefilter_total_us should not be in dashboard response"
        );
        assert!(
            body.get("deep_analysis_total_ms").is_none(),
            "deep_analysis_total_ms should not be in dashboard response"
        );
    }

    #[tokio::test]
    async fn test_sentinel_metrics_zero_state() {
        let port = next_port();
        spawn_server(port).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/sentinel/metrics"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["blocks_scanned"], 0);
        assert_eq!(body["txs_scanned"], 0);
        assert_eq!(body["txs_flagged"], 0);
        assert_eq!(body["alerts_emitted"], 0);
    }

    #[tokio::test]
    async fn test_sentinel_history_endpoint() {
        let port = next_port();
        let alerts = vec![
            make_alert(100, AlertPriority::High, 0x01),
            make_alert(101, AlertPriority::Medium, 0x02),
            make_alert(102, AlertPriority::Critical, 0x03),
        ];
        spawn_server_with_alerts(port, &alerts).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/sentinel/history"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("application/json"),
            "expected JSON content-type, got: {ct}"
        );

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["total"], 3);
        assert_eq!(body["alerts"].as_array().unwrap().len(), 3);
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 20);
    }

    #[tokio::test]
    async fn test_sentinel_history_empty() {
        let port = next_port();
        spawn_server(port).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/sentinel/history"))
            .await
            .expect("request failed");

        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["total"], 0);
        assert_eq!(body["alerts"].as_array().unwrap().len(), 0);
        assert_eq!(body["page"], 1);
        assert_eq!(body["page_size"], 20);
    }

    #[tokio::test]
    async fn test_sentinel_history_pagination() {
        let port = next_port();
        let alerts: Vec<SentinelAlert> = (0..5)
            .map(|i| make_alert(100 + i, AlertPriority::High, i as u8))
            .collect();
        spawn_server_with_alerts(port, &alerts).await;

        let resp = reqwest::get(format!(
            "http://127.0.0.1:{port}/sentinel/history?page=1&page_size=2"
        ))
        .await
        .expect("request failed");

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["total"], 5);
        assert_eq!(body["alerts"].as_array().unwrap().len(), 2);
        assert_eq!(body["page"], 1);
    }

    #[tokio::test]
    async fn test_sentinel_history_priority_filter() {
        let port = next_port();
        let alerts = vec![
            make_alert(100, AlertPriority::Medium, 0x01),
            make_alert(101, AlertPriority::High, 0x02),
            make_alert(102, AlertPriority::Critical, 0x03),
        ];
        spawn_server_with_alerts(port, &alerts).await;

        let resp = reqwest::get(format!(
            "http://127.0.0.1:{port}/sentinel/history?priority=high"
        ))
        .await
        .expect("request failed");

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["total"], 2);
    }

    #[tokio::test]
    async fn test_sentinel_history_block_range_filter() {
        let port = next_port();
        let alerts: Vec<SentinelAlert> = (100..110)
            .map(|i| make_alert(i, AlertPriority::High, i as u8))
            .collect();
        spawn_server_with_alerts(port, &alerts).await;

        let resp = reqwest::get(format!(
            "http://127.0.0.1:{port}/sentinel/history?block_from=103&block_to=106"
        ))
        .await
        .expect("request failed");

        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        assert_eq!(body["total"], 4);
    }

    #[tokio::test]
    async fn test_sentinel_history_sort_newest_first() {
        let port = next_port();
        let alerts = vec![
            make_alert(100, AlertPriority::High, 0x01),
            make_alert(105, AlertPriority::High, 0x02),
            make_alert(102, AlertPriority::High, 0x03),
        ];
        spawn_server_with_alerts(port, &alerts).await;

        let resp = reqwest::get(format!("http://127.0.0.1:{port}/sentinel/history"))
            .await
            .expect("request failed");
        let body: serde_json::Value = resp.json().await.expect("invalid JSON");
        let first_block = body["alerts"][0]["block_number"].as_u64().unwrap();
        assert_eq!(first_block, 105);
    }

    #[tokio::test]
    async fn test_cors_headers() {
        let port = next_port();
        spawn_server(port).await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://127.0.0.1:{port}/sentinel/metrics"))
            .header("Origin", "http://localhost:4321")
            .send()
            .await
            .expect("request failed");

        let cors_header = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cors_header, "*", "CORS allow-origin should be wildcard");
    }

    #[tokio::test]
    async fn test_cors_preflight() {
        let port = next_port();
        spawn_server(port).await;

        let client = reqwest::Client::new();
        let resp = client
            .request(
                reqwest::Method::OPTIONS,
                format!("http://127.0.0.1:{port}/sentinel/metrics"),
            )
            .header("Origin", "http://localhost:4321")
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await
            .expect("preflight request failed");

        let cors_header = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cors_header, "*", "CORS preflight should allow any origin");
    }
}
