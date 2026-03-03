//! Demo: RPC-mode Sentinel — monitors Ethereum via JSON-RPC without a local full node.
//!
//! Usage:
//!   ALCHEMY_API_KEY=your_key cargo run --example sentinel_rpc_demo --features sentinel,autopsy
//!
//! This example starts the RPC sentinel service and prints any alerts to stderr.
//! It polls the live Ethereum mainnet for new blocks and runs the pre-filter
//! heuristics. Suspicious transactions are flagged and printed.
//!
//! Press Ctrl+C to stop.

#[cfg(all(feature = "sentinel", feature = "autopsy"))]
#[tokio::main]
async fn main() {
    use argus::sentinel::rpc_poller::RpcPollerConfig;
    use argus::sentinel::rpc_service::{RpcSentinelConfig, RpcSentinelService};
    use argus::sentinel::types::{AnalysisConfig, SentinelAlert};
    use std::time::Duration;
    use tokio::sync::mpsc;

    let api_key = std::env::var("ALCHEMY_API_KEY")
        .expect("ALCHEMY_API_KEY must be set (e.g., export ALCHEMY_API_KEY=your_key)");
    let rpc_url = format!("https://eth-mainnet.g.alchemy.com/v2/{api_key}");

    let masked_url = if rpc_url.len() > 40 {
        format!(
            "{}...{}",
            &rpc_url[..40],
            &rpc_url[rpc_url.len().saturating_sub(4)..]
        )
    } else {
        rpc_url.clone()
    };
    eprintln!("[rpc_demo] Starting RPC sentinel on {masked_url}");
    eprintln!("[rpc_demo] Press Ctrl+C to stop.");

    let config = RpcSentinelConfig {
        rpc_url: rpc_url.clone(),
        poller_config: RpcPollerConfig {
            rpc_url: rpc_url.clone(),
            poll_interval: Duration::from_secs(2),
            rpc_config: argus::autopsy::rpc_client::RpcConfig::default(),
        },
        analysis_config: AnalysisConfig {
            prefilter_alert_mode: true,
            ..Default::default()
        },
        prefilter_only: true, // safe default — works with any node type
    };

    let (alert_tx, mut alert_rx) = mpsc::channel::<SentinelAlert>(64);

    let service = RpcSentinelService::start(config, alert_tx).await;

    // Print alerts until Ctrl+C
    let alert_task = tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            eprintln!(
                "[ALERT] block={} tx_index={} priority={:?} score={:.2}",
                alert.block_number, alert.tx_index, alert.alert_priority, alert.suspicion_score
            );
            eprintln!("  summary: {}", alert.summary);
        }
    });

    // Wait for Ctrl+C
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");

    eprintln!("[rpc_demo] Shutting down…");
    service.shutdown().await;
    alert_task.abort();
}

#[cfg(not(all(feature = "sentinel", feature = "autopsy")))]
fn main() {
    eprintln!("This demo requires --features sentinel,autopsy");
    std::process::exit(1);
}
