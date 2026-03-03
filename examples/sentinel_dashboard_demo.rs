//! Sentinel Dashboard-Integrated Demo
//!
//! Serves a mini HTTP+WS server compatible with the Astro+React dashboard at
//! `dashboard/src/pages/sentinel.astro`. Three endpoints:
//!
//!   GET  /sentinel/metrics  — JSON metrics snapshot
//!   GET  /sentinel/history  — paginated alert history (JSONL-backed)
//!   GET  /sentinel/ws       — WebSocket real-time alert feed
//!
//! A background block generator feeds synthetic blocks every 3 seconds.
//!
//! ## Usage
//!
//! ```bash
//! # Terminal 1: start the demo server
//! cargo run -p argus --features sentinel --example sentinel_dashboard_demo
//!
//! # Terminal 2: start the dashboard
//! cd dashboard && SENTINEL_API=http://localhost:3001 npm run dev
//! # Open http://localhost:4321/sentinel
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

use bytes::Bytes;
use ethrex_blockchain::BlockObserver;
use ethrex_common::types::{
    Block, BlockBody, BlockHeader, EIP1559Transaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};
use ethrex_storage::{EngineType, Store};

use argus::sentinel::alert::{AlertDispatcher, JsonlFileAlertHandler};
use argus::sentinel::history::{AlertHistory, AlertQueryParams, SortOrder};
use argus::sentinel::metrics::SentinelMetrics;
use argus::sentinel::service::{AlertHandler, SentinelService};
use argus::sentinel::types::{AlertPriority, AnalysisConfig, SentinelConfig};
use argus::sentinel::ws_broadcaster::{WsAlertBroadcaster, WsAlertHandler};

// ── Shared Application State ────────────────────────────────────────────

struct AppState {
    metrics: Arc<SentinelMetrics>,
    broadcaster: Arc<WsAlertBroadcaster>,
    history: AlertHistory,
}

// ── Collecting Alert Handler (console output) ───────────────────────────

struct ConsoleHandler {
    count: Arc<AtomicUsize>,
}

impl ConsoleHandler {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        (
            Self {
                count: count.clone(),
            },
            count,
        )
    }
}

impl AlertHandler for ConsoleHandler {
    fn on_alert(&self, alert: argus::sentinel::types::SentinelAlert) {
        let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "  [ALERT #{n}] block={} tx_idx={} priority={:?} score={:.2} — {}",
            alert.block_number,
            alert.tx_index,
            alert.alert_priority,
            alert.suspicion_score,
            alert.summary,
        );
    }
}

// ── Block/TX Builders (reused from sentinel_realtime_demo) ──────────────

fn transfer_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xdd;
    bytes[1] = 0xf2;
    bytes[2] = 0x52;
    bytes[3] = 0xad;
    H256::from(bytes)
}

fn flash_loan_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0x63;
    bytes[1] = 0x1c;
    bytes[2] = 0x02;
    bytes[3] = 0x4d;
    H256::from(bytes)
}

fn aave_v2_address() -> Address {
    let bytes =
        hex::decode("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9").expect("valid hex address");
    Address::from_slice(&bytes)
}

fn benign_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0xBEEF)),
        value: U256::from(1_000_000_000_000_000_000_u64),
        gas_limit: 21_000,
        data: Bytes::new(),
        ..Default::default()
    })
}

fn benign_receipt(gas_used: u64) -> Receipt {
    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: true,
        cumulative_gas_used: gas_used,
        logs: vec![],
    }
}

fn flash_loan_tx() -> Transaction {
    let calldata = vec![0xab, 0x9c, 0x4b, 0x5d, 0x00, 0x00, 0x00, 0x00];
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(aave_v2_address()),
        gas_limit: 3_000_000,
        data: Bytes::from(calldata),
        ..Default::default()
    })
}

fn flash_loan_receipt(cumulative_gas: u64) -> Receipt {
    let mut logs = Vec::new();
    logs.push(Log {
        address: aave_v2_address(),
        topics: vec![flash_loan_topic()],
        data: Bytes::from(vec![0u8; 64]),
    });
    for i in 0..6 {
        logs.push(Log {
            address: Address::from_low_u64_be(0xDA10 + i),
            topics: vec![
                transfer_topic(),
                H256::from_low_u64_be(0x1000 + i),
                H256::from_low_u64_be(0x2000 + i),
            ],
            data: Bytes::from(vec![0u8; 32]),
        });
    }
    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: true,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

fn reverted_high_gas_tx() -> Transaction {
    Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(Address::from_low_u64_be(0xDEAD)),
        value: U256::from(5_000_000_000_000_000_000_u64),
        gas_limit: 1_000_000,
        data: Bytes::new(),
        ..Default::default()
    })
}

fn reverted_receipt(cumulative_gas: u64) -> Receipt {
    Receipt {
        tx_type: TxType::EIP1559,
        succeeded: false,
        cumulative_gas_used: cumulative_gas,
        logs: vec![],
    }
}

fn build_mixed_block(block_number: u64, txs: Vec<Transaction>) -> Block {
    Block {
        header: BlockHeader {
            number: block_number,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        body: BlockBody {
            transactions: txs,
            ..Default::default()
        },
    }
}

// ── Axum Handlers ───────────────────────────────────────────────────────

/// GET /sentinel/metrics — returns JSON with 4 dashboard-expected fields.
async fn handle_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.metrics.snapshot();
    Json(serde_json::json!({
        "blocks_scanned": snap.blocks_scanned,
        "txs_scanned": snap.txs_scanned,
        "txs_flagged": snap.txs_flagged,
        "alerts_emitted": snap.alerts_emitted,
    }))
}

/// Query parameters for the history endpoint (from dashboard JS).
#[derive(Debug, serde::Deserialize)]
struct HistoryQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    priority: Option<String>,
    block_from: Option<u64>,
    block_to: Option<u64>,
    pattern_type: Option<String>,
}

/// GET /sentinel/history — returns paginated alert history.
///
/// Dashboard expects `{ alerts, total, page, page_size }` — note `total`
/// instead of `total_count` from the Rust struct.
async fn handle_history(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HistoryQuery>,
) -> impl IntoResponse {
    let min_priority = q.priority.as_deref().and_then(|p| match p {
        "Medium" => Some(AlertPriority::Medium),
        "High" => Some(AlertPriority::High),
        "Critical" => Some(AlertPriority::Critical),
        _ => None,
    });

    let block_range = match (q.block_from, q.block_to) {
        (Some(from), Some(to)) => Some((from, to)),
        (Some(from), None) => Some((from, u64::MAX)),
        (None, Some(to)) => Some((0, to)),
        (None, None) => None,
    };

    let params = AlertQueryParams {
        page: q.page.unwrap_or(1),
        page_size: q.page_size.unwrap_or(20),
        min_priority,
        block_range,
        pattern_type: q.pattern_type,
        sort_order: SortOrder::Newest,
    };

    let result = state.history.query(&params);

    // Re-map alerts: transform suspicion_reasons from Rust's externally-tagged
    // format to dashboard's `{ type, details }` format.
    let alerts: Vec<serde_json::Value> = result
        .alerts
        .iter()
        .map(|alert| {
            let mut v = serde_json::to_value(alert).unwrap_or_default();
            if let Some(reasons) = v.get("suspicion_reasons").cloned() {
                let remapped = remap_suspicion_reasons(&reasons);
                v.as_object_mut()
                    .expect("alert is object")
                    .insert("suspicion_reasons".to_string(), remapped);
            }
            v
        })
        .collect();

    Json(serde_json::json!({
        "alerts": alerts,
        "total": result.total_count,
        "page": result.page,
        "page_size": result.page_size,
    }))
}

/// GET /sentinel/ws — WebSocket upgrade for real-time alert feed.
async fn handle_ws(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| ws_session(socket, state.broadcaster.clone()))
}

/// WebSocket session: reads from mpsc receiver and sends JSON text frames.
///
/// Remaps `suspicion_reasons` from Rust's externally-tagged enum format to
/// the dashboard's `{ type, details }` format before sending.
async fn ws_session(mut socket: WebSocket, broadcaster: Arc<WsAlertBroadcaster>) {
    let rx = broadcaster.subscribe();

    loop {
        match rx.try_recv() {
            Ok(json_str) => {
                let remapped = remap_alert_json(&json_str);
                if socket.send(Message::Text(remapped.into())).await.is_err() {
                    break;
                }
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                break;
            }
        }
    }
}

/// Remap a raw JSON alert string so `suspicion_reasons` uses `{ type, details }`.
fn remap_alert_json(json_str: &str) -> String {
    let mut v: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return json_str.to_string(),
    };
    if let Some(reasons) = v.get("suspicion_reasons").cloned() {
        let remapped = remap_suspicion_reasons(&reasons);
        v.as_object_mut()
            .expect("alert is object")
            .insert("suspicion_reasons".to_string(), remapped);
    }
    serde_json::to_string(&v).unwrap_or_else(|_| json_str.to_string())
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
                    return serde_json::json!({
                        "type": variant_name,
                        "details": details,
                    });
                }
            }
            // Unit variant or string — wrap as type-only
            if let Some(s) = reason.as_str() {
                return serde_json::json!({ "type": s });
            }
            reason.clone()
        })
        .collect();

    serde_json::Value::Array(remapped)
}

// ── Background Block Generator ──────────────────────────────────────────

fn spawn_block_generator(service: Arc<SentinelService>, alert_count: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        let mut block_number: u64 = 18_000_000;
        let mut cycle: u64 = 0;

        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));

            // Mix of benign and suspicious blocks
            let (txs, receipts) = match cycle % 3 {
                0 => {
                    // Benign-only block
                    (
                        vec![benign_tx(), benign_tx()],
                        vec![benign_receipt(21_000), benign_receipt(42_000)],
                    )
                }
                1 => {
                    // Flash loan + benign
                    (
                        vec![benign_tx(), flash_loan_tx()],
                        vec![benign_receipt(21_000), flash_loan_receipt(2_521_000)],
                    )
                }
                _ => {
                    // Reverted high-gas + flash loan
                    (
                        vec![reverted_high_gas_tx(), flash_loan_tx(), benign_tx()],
                        vec![
                            reverted_receipt(950_000),
                            flash_loan_receipt(3_450_000),
                            benign_receipt(3_471_000),
                        ],
                    )
                }
            };

            let tx_count = txs.len();
            let block = build_mixed_block(block_number, txs);
            let alerts_before = alert_count.load(Ordering::SeqCst);

            service.on_block_committed(block, receipts);

            // Brief pause to let worker process
            std::thread::sleep(std::time::Duration::from_millis(200));
            let alerts_after = alert_count.load(Ordering::SeqCst);
            let new_alerts = alerts_after - alerts_before;

            println!(
                "  Block #{block_number}: {tx_count} TXs, {new_alerts} new alert(s) \
                 [total alerts: {alerts_after}]"
            );

            block_number += 1;
            cycle += 1;
        }
    });
}

// ── Main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!();
    println!("================================================================");
    println!("  Sentinel Dashboard Demo — HTTP+WS Server");
    println!("================================================================");
    println!();

    // ── Set up JSONL history file ───────────────────────────────────────
    let jsonl_path = std::env::temp_dir().join("sentinel_dashboard_demo.jsonl");
    let _ = std::fs::remove_file(&jsonl_path);
    println!("  JSONL path: {}", jsonl_path.display());

    // ── Build alert handler pipeline ────────────────────────────────────
    let broadcaster = Arc::new(WsAlertBroadcaster::new());
    let ws_handler = WsAlertHandler::new(broadcaster.clone());
    let jsonl_handler = JsonlFileAlertHandler::new(jsonl_path.clone());
    let (console_handler, alert_count) = ConsoleHandler::new();

    let mut dispatcher = AlertDispatcher::default();
    dispatcher.add_handler(Box::new(ws_handler));
    dispatcher.add_handler(Box::new(jsonl_handler));
    dispatcher.add_handler(Box::new(console_handler));

    // ── Create SentinelService ──────────────────────────────────────────
    let store = Store::new("", EngineType::InMemory).expect("in-memory store");
    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 20_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(dispatcher));
    let metrics = service.metrics();
    let service = Arc::new(service);

    // ── Build Axum app ──────────────────────────────────────────────────
    let history = AlertHistory::new(jsonl_path);
    let state = Arc::new(AppState {
        metrics,
        broadcaster: broadcaster.clone(),
        history,
    });

    let app = Router::new()
        .route("/sentinel/metrics", get(handle_metrics))
        .route("/sentinel/history", get(handle_history))
        .route("/sentinel/ws", get(handle_ws))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // ── Start background block generator ────────────────────────────────
    spawn_block_generator(service.clone(), alert_count);

    // ── Start HTTP server ───────────────────────────────────────────────
    let bind_addr = "0.0.0.0:3001";
    println!("  Server listening on http://{bind_addr}");
    println!();
    println!("  Endpoints:");
    println!("    GET  http://localhost:3001/sentinel/metrics");
    println!("    GET  http://localhost:3001/sentinel/history?page=1&page_size=5");
    println!("    WS   ws://localhost:3001/sentinel/ws");
    println!();
    println!("  Dashboard:");
    println!("    cd dashboard && npm run dev");
    println!("    Open http://localhost:4321/sentinel");
    println!("    Pass props: apiBase=\"http://localhost:3001/sentinel/...\"");
    println!();
    println!("  Generating blocks every 3 seconds...");
    println!("----------------------------------------------------------------");

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("bind address");
    axum::serve(listener, app).await.expect("server error");
}
