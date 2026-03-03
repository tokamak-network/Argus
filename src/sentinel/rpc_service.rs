//! RPC-mode Sentinel service — runs the full detection pipeline using any JSON-RPC endpoint.
//!
//! `RpcSentinelService` polls an Ethereum node via JSON-RPC, converts each incoming
//! block into ethrex-native types, and runs the same two-stage detection pipeline
//! used by the Store-mode service: pre-filter heuristics followed by optional deep
//! opcode-level replay.
//!
//! Think of it like a security guard watching a live camera feed (RPC poller) instead
//! of reviewing footage from an internal hard drive (local Store). Same guard, same
//! skills — different data source.
//!
//! # Modes
//!
//! - **prefilter_only = false** (default): Deep RPC replay via `replay_tx_from_rpc`.
//!   Requires an archive node.
//! - **prefilter_only = true**: Receipt-based heuristics only. Compatible with any
//!   full node. Lower fidelity but faster and cheaper.

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::autopsy::rpc_client::{RpcBlock, RpcReceipt};

use super::metrics::SentinelMetrics;
use super::pre_filter::PreFilter;
use super::rpc_poller::{RpcBlockPoller, RpcPollerConfig};
use super::rpc_replay::replay_tx_from_rpc;
use super::rpc_types::{rpc_block_to_ethrex, rpc_receipt_to_ethrex};
use super::types::{
    AlertPriority, AnalysisConfig, SentinelAlert, SentinelConfig, SuspicionReason, SuspiciousTx,
};

/// Configuration for the RPC-mode sentinel service.
#[derive(Debug, Clone)]
pub struct RpcSentinelConfig {
    /// Ethereum RPC endpoint URL.
    pub rpc_url: String,
    /// Block poller configuration (poll interval, timeouts, retries).
    pub poller_config: RpcPollerConfig,
    /// Deep analysis configuration (step limits, confidence thresholds).
    pub analysis_config: AnalysisConfig,
    /// When true, skip deep RPC replay and emit alerts from pre-filter results only.
    /// Use this with standard full nodes that don't have archive state.
    pub prefilter_only: bool,
}

impl RpcSentinelConfig {
    /// Create a config with sensible defaults for the given RPC URL.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let rpc_url = rpc_url.into();
        let poller_config = RpcPollerConfig::new(rpc_url.clone());
        Self {
            rpc_url,
            poller_config,
            analysis_config: AnalysisConfig {
                prefilter_alert_mode: true, // emit alerts even without deep analysis
                ..Default::default()
            },
            prefilter_only: false,
        }
    }
}

impl Default for RpcSentinelConfig {
    fn default() -> Self {
        Self::new("http://localhost:8545")
    }
}

/// RPC-mode sentinel service.
///
/// Spawns an async background task that:
/// 1. Polls the chain for new blocks via `RpcBlockPoller`
/// 2. Converts `(RpcBlock, Vec<RpcReceipt>)` to ethrex types
/// 3. Runs `PreFilter::scan_block` on each block
/// 4. Optionally deep-replays suspicious TXs via `replay_tx_from_rpc`
/// 5. Emits `SentinelAlert`s through the provided channel
pub struct RpcSentinelService {
    metrics: Arc<SentinelMetrics>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl RpcSentinelService {
    /// Start the RPC sentinel service.
    ///
    /// Spawns a background tokio task and returns immediately. Alerts are sent
    /// through `alert_tx`. Call [`shutdown`](Self::shutdown) to stop the service.
    pub async fn start(config: RpcSentinelConfig, alert_tx: mpsc::Sender<SentinelAlert>) -> Self {
        let metrics = Arc::new(SentinelMetrics::new());
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let worker_metrics = metrics.clone();
        let task_handle = tokio::spawn(async move {
            service_loop(config, alert_tx, worker_metrics, shutdown_rx).await;
        });

        Self {
            metrics,
            shutdown_tx: Some(shutdown_tx),
            task_handle: Some(task_handle),
        }
    }

    /// Returns a shared reference to the pipeline metrics.
    pub fn metrics(&self) -> Arc<SentinelMetrics> {
        self.metrics.clone()
    }

    /// Signal the background task to stop and wait for it to exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Core service loop — runs in a spawned tokio task.
async fn service_loop(
    config: RpcSentinelConfig,
    alert_tx: mpsc::Sender<SentinelAlert>,
    metrics: Arc<SentinelMetrics>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let poller = RpcBlockPoller::new(config.poller_config);
    let mut block_rx = poller.start().await;

    let sentinel_config = SentinelConfig::default();
    let pre_filter = PreFilter::new(sentinel_config);
    let rpc_url = config.rpc_url.clone();
    let analysis_config = config.analysis_config.clone();
    let prefilter_only = config.prefilter_only;

    loop {
        tokio::select! {
            // Shutdown signal received
            _ = &mut shutdown_rx => {
                poller.stop().await;
                break;
            }
            // New block from poller
            maybe_block = block_rx.recv() => {
                let Some((rpc_block, rpc_receipts)) = maybe_block else {
                    // Channel closed — poller stopped
                    break;
                };
                process_rpc_block(
                    &rpc_block,
                    &rpc_receipts,
                    ProcessContext {
                        pre_filter: &pre_filter,
                        rpc_url: &rpc_url,
                        analysis_config: &analysis_config,
                        prefilter_only,
                        alert_tx: &alert_tx,
                        metrics: &metrics,
                    },
                )
                .await;
            }
        }
    }
}

/// Shared processing context passed to `process_rpc_block`.
struct ProcessContext<'a> {
    pre_filter: &'a PreFilter,
    rpc_url: &'a str,
    analysis_config: &'a AnalysisConfig,
    prefilter_only: bool,
    alert_tx: &'a mpsc::Sender<SentinelAlert>,
    metrics: &'a SentinelMetrics,
}

/// Process one `(RpcBlock, Vec<RpcReceipt>)` pair through the detection pipeline.
async fn process_rpc_block(
    rpc_block: &RpcBlock,
    rpc_receipts: &[RpcReceipt],
    ctx: ProcessContext<'_>,
) {
    let ProcessContext {
        pre_filter,
        rpc_url,
        analysis_config,
        prefilter_only,
        alert_tx,
        metrics,
    } = ctx;
    // Convert RPC types to ethrex types for pre-filter
    let ethrex_block = match rpc_block_to_ethrex(rpc_block) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[rpc_sentinel] block type conversion failed: {e}");
            return;
        }
    };
    let ethrex_receipts: Vec<_> = rpc_receipts.iter().map(rpc_receipt_to_ethrex).collect();

    metrics.increment_blocks_scanned();
    metrics.increment_txs_scanned(ethrex_block.body.transactions.len() as u64);

    // Stage 1: Pre-filter (receipt-based heuristics)
    let prefilter_start = Instant::now();
    let suspicious_txs = pre_filter.scan_block(
        &ethrex_block.body.transactions,
        &ethrex_receipts,
        &ethrex_block.header,
    );
    let prefilter_us = prefilter_start.elapsed().as_micros() as u64;
    metrics.add_prefilter_us(prefilter_us);
    metrics.increment_txs_flagged(suspicious_txs.len() as u64);

    if suspicious_txs.is_empty() {
        return;
    }

    // Stage 2: Optionally deep-replay each suspicious TX
    if prefilter_only {
        // Fast path: emit lightweight pre-filter alerts without replay
        for suspicion in &suspicious_txs {
            let alert = build_prefilter_alert(rpc_block, suspicion);
            metrics.increment_alerts_emitted();
            if alert_tx.send(alert).await.is_err() {
                return; // receiver dropped — stop processing
            }
        }
        return;
    }

    // Deep analysis path: replay all suspicious TXs in parallel
    let block_number = rpc_block.header.number;
    let prefilter_alert_mode = analysis_config.prefilter_alert_mode;

    let mut join_set = tokio::task::JoinSet::new();
    for suspicion in &suspicious_txs {
        let rpc_url_clone = rpc_url.to_string();
        let rpc_block_clone = rpc_block.clone();
        let analysis_config_clone = analysis_config.clone();
        let tx_index = suspicion.tx_index;

        join_set.spawn_blocking(move || {
            let result = replay_tx_from_rpc(
                &rpc_url_clone,
                block_number,
                tx_index,
                &rpc_block_clone,
                &analysis_config_clone,
            );
            (tx_index, result)
        });
    }

    // Build an index from tx_index to suspicion for alert construction
    let suspicion_by_index: std::collections::HashMap<usize, &SuspiciousTx> =
        suspicious_txs.iter().map(|s| (s.tx_index, s)).collect();

    let analysis_start = Instant::now();
    while let Some(join_result) = join_set.join_next().await {
        let (tx_index, replay_result) = match join_result {
            Ok(val) => val,
            Err(_) => continue, // task panicked — skip
        };

        let Some(suspicion) = suspicion_by_index.get(&tx_index) else {
            continue;
        };

        let alert = match replay_result {
            Ok(replay) => {
                // Deep analysis succeeded — build enriched alert
                build_deep_alert(
                    rpc_block,
                    suspicion,
                    replay.trace.steps.len(),
                    replay.trace.success,
                )
            }
            Err(_) if prefilter_alert_mode => {
                // Deep analysis failed but prefilter_alert_mode is on
                build_prefilter_alert(rpc_block, suspicion)
            }
            Err(_) => {
                // Deep analysis failed and mode is strict — skip alert
                continue;
            }
        };

        metrics.increment_alerts_emitted();
        if alert_tx.send(alert).await.is_err() {
            return; // receiver dropped — stop processing
        }
    }
    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
    metrics.add_deep_analysis_ms(analysis_ms);
}

/// Map a `SuspicionReason` variant to its short display name.
fn reason_display_name(r: &SuspicionReason) -> &'static str {
    match r {
        SuspicionReason::FlashLoanSignature { .. } => "flash-loan",
        SuspicionReason::HighValueWithRevert { .. } => "high-value-revert",
        SuspicionReason::MultipleErc20Transfers { .. } => "erc20-transfers",
        SuspicionReason::KnownContractInteraction { .. } => "known-contract",
        SuspicionReason::UnusualGasPattern { .. } => "unusual-gas",
        SuspicionReason::SelfDestructDetected => "self-destruct",
        SuspicionReason::PriceOracleWithSwap { .. } => "oracle-swap",
    }
}

/// Build the common fields shared by prefilter and deep alerts.
fn build_alert_base(rpc_block: &RpcBlock, suspicion: &SuspiciousTx) -> SentinelAlert {
    SentinelAlert {
        block_number: rpc_block.header.number,
        block_hash: rpc_block.header.hash,
        tx_hash: suspicion.tx_hash,
        tx_index: suspicion.tx_index,
        alert_priority: AlertPriority::from_score(suspicion.score),
        suspicion_reasons: suspicion.reasons.clone(),
        suspicion_score: suspicion.score,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: ethrex_common::U256::zero(),
        summary: String::new(),
        total_steps: 0,
        feature_vector: None,
    }
}

/// Build a lightweight `SentinelAlert` from pre-filter results only (no replay).
fn build_prefilter_alert(rpc_block: &RpcBlock, suspicion: &SuspiciousTx) -> SentinelAlert {
    let reason_names: Vec<&str> = suspicion.reasons.iter().map(reason_display_name).collect();
    let summary = format!(
        "Pre-filter alert (RPC): {} (score={:.2})",
        reason_names.join(", "),
        suspicion.score
    );
    SentinelAlert {
        summary,
        ..build_alert_base(rpc_block, suspicion)
    }
}

/// Build an enriched `SentinelAlert` after successful RPC replay.
fn build_deep_alert(
    rpc_block: &RpcBlock,
    suspicion: &SuspiciousTx,
    total_steps: usize,
    success: bool,
) -> SentinelAlert {
    let reason_names: Vec<&str> = suspicion.reasons.iter().map(reason_display_name).collect();
    let summary = format!(
        "Deep RPC alert: {} (score={:.2}, steps={total_steps}, success={success})",
        reason_names.join(", "),
        suspicion.score
    );
    SentinelAlert {
        summary,
        total_steps,
        ..build_alert_base(rpc_block, suspicion)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopsy::rpc_client::{RpcBlock, RpcBlockHeader, RpcReceipt, RpcTransaction};
    use ethrex_common::{Address, H256, U256};
    use std::time::Duration;

    fn make_rpc_block_header(number: u64) -> RpcBlockHeader {
        RpcBlockHeader {
            hash: H256::from_low_u64_be(number),
            number,
            timestamp: 1_700_000_000 + number,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            coinbase: Address::from_low_u64_be(0x01),
        }
    }

    fn make_rpc_block(number: u64) -> RpcBlock {
        RpcBlock {
            header: make_rpc_block_header(number),
            transactions: vec![],
        }
    }

    // --- Configuration tests ---

    #[test]
    fn test_rpc_sentinel_config_defaults() {
        let config = RpcSentinelConfig::default();
        assert_eq!(config.rpc_url, "http://localhost:8545");
        assert!(!config.prefilter_only);
        assert!(config.analysis_config.prefilter_alert_mode);
        assert_eq!(config.analysis_config.max_steps, 1_000_000);
    }

    #[test]
    fn test_rpc_sentinel_config_new() {
        let config = RpcSentinelConfig::new("https://mainnet.infura.io/v3/KEY");
        assert_eq!(config.rpc_url, "https://mainnet.infura.io/v3/KEY");
        assert_eq!(
            config.poller_config.rpc_url,
            "https://mainnet.infura.io/v3/KEY"
        );
    }

    #[test]
    fn test_rpc_sentinel_config_prefilter_only() {
        let mut config = RpcSentinelConfig::default();
        config.prefilter_only = true;
        assert!(config.prefilter_only);
    }

    // --- Service lifecycle tests ---

    #[tokio::test]
    async fn test_service_lifecycle() {
        let (alert_tx, _alert_rx) = mpsc::channel(16);
        // Use a non-routable address so the poller fails immediately
        let mut config = RpcSentinelConfig::default();
        config.rpc_url = "http://127.0.0.1:19998".into();
        config.poller_config = super::super::rpc_poller::RpcPollerConfig {
            rpc_url: "http://127.0.0.1:19998".into(),
            poll_interval: Duration::from_millis(50),
            rpc_config: crate::autopsy::rpc_client::RpcConfig {
                timeout: Duration::from_millis(100),
                connect_timeout: Duration::from_millis(100),
                max_retries: 0,
                base_backoff: Duration::from_millis(10),
            },
        };

        let service = RpcSentinelService::start(config, alert_tx).await;
        // Metrics should be initialized at zero
        let snapshot = service.metrics().snapshot();
        assert_eq!(snapshot.blocks_scanned, 0);
        // Shutdown should not panic
        service.shutdown().await;
    }

    #[tokio::test]
    async fn test_service_metrics_accessible() {
        let (alert_tx, _alert_rx) = mpsc::channel(16);
        let config = RpcSentinelConfig::default();
        let service = RpcSentinelService::start(config, alert_tx).await;
        let metrics = service.metrics();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.alerts_emitted, 0);
        assert_eq!(snapshot.txs_scanned, 0);
        service.shutdown().await;
    }

    // --- Prefilter-only mode test ---

    #[tokio::test]
    async fn test_prefilter_only_mode() {
        // In prefilter_only mode, the deep replay is skipped.
        // We verify the config flag is respected by the service constructor.
        let (alert_tx, _alert_rx) = mpsc::channel(16);
        let mut config = RpcSentinelConfig::default();
        config.prefilter_only = true;
        config.poller_config.rpc_url = "http://127.0.0.1:19997".into();
        config.rpc_url = "http://127.0.0.1:19997".into();

        let service = RpcSentinelService::start(config, alert_tx).await;
        // Service starts without panic — prefilter_only flag is accepted
        let snapshot = service.metrics().snapshot();
        assert_eq!(snapshot.blocks_scanned, 0);
        service.shutdown().await;
    }

    // --- Alert emission test (synthetic, offline) ---

    #[tokio::test]
    async fn test_alert_emission_prefilter_only() {
        // Build a suspicious block with a high-value-revert TX and feed it directly
        // through process_rpc_block in prefilter_only mode to verify alert emission.

        let (alert_tx, mut alert_rx) = mpsc::channel(16);
        let metrics = Arc::new(SentinelMetrics::new());

        // Build a block with one high-value transaction that failed (revert)
        let high_value = U256::from(2_000_000_000_000_000_000_u64); // 2 ETH
        let tx = RpcTransaction {
            hash: H256::from_low_u64_be(0x1234),
            from: Address::from_low_u64_be(0x100),
            to: Some(Address::from_low_u64_be(0x42)),
            value: high_value,
            input: vec![],
            gas: 600_000,
            gas_price: Some(2_000_000_000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: 0,
            block_number: Some(100),
        };
        let rpc_block = RpcBlock {
            header: make_rpc_block_header(100),
            transactions: vec![tx],
        };
        // Receipt: TX failed (status=false) with high gas usage
        let receipt = RpcReceipt {
            status: false, // reverted
            cumulative_gas_used: 550_000,
            logs: vec![],
            transaction_hash: H256::from_low_u64_be(0x1234),
            transaction_index: 0,
            gas_used: 550_000,
        };

        let sentinel_config = SentinelConfig {
            min_gas_used: 500_000,
            min_value_wei: U256::from(1_000_000_000_000_000_000_u64), // 1 ETH threshold
            // Lower threshold so HighValueWithRevert (score=0.3) is enough to flag
            suspicion_threshold: 0.25,
            ..Default::default()
        };
        let pre_filter = PreFilter::new(sentinel_config);
        let analysis_config = AnalysisConfig {
            prefilter_alert_mode: true,
            ..Default::default()
        };

        process_rpc_block(
            &rpc_block,
            &[receipt],
            super::ProcessContext {
                pre_filter: &pre_filter,
                rpc_url: "http://127.0.0.1:1", // unreachable — won't be called in prefilter_only
                analysis_config: &analysis_config,
                prefilter_only: true,
                alert_tx: &alert_tx,
                metrics: &metrics,
            },
        )
        .await;

        // Drop alert_tx so recv() doesn't block
        drop(alert_tx);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.blocks_scanned, 1);
        assert_eq!(snapshot.txs_scanned, 1);
        assert!(
            snapshot.txs_flagged > 0,
            "expected TX to be flagged by pre-filter (high-value revert above threshold)"
        );
        let alert = alert_rx.recv().await.expect("expected alert");
        assert_eq!(alert.block_number, 100);
        assert_eq!(alert.tx_index, 0);
        assert_eq!(snapshot.alerts_emitted, 1);
    }

    // --- Helper: verify build_prefilter_alert produces correct output ---

    #[test]
    fn test_build_prefilter_alert_fields() {
        use super::super::types::{AlertPriority, SuspicionReason};

        let rpc_block = make_rpc_block(42);
        let suspicion = SuspiciousTx {
            tx_hash: H256::from_low_u64_be(0xbeef),
            tx_index: 3,
            reasons: vec![SuspicionReason::SelfDestructDetected],
            score: 0.8,
            priority: AlertPriority::High,
        };

        let alert = build_prefilter_alert(&rpc_block, &suspicion);
        assert_eq!(alert.block_number, 42);
        assert_eq!(alert.tx_index, 3);
        assert_eq!(alert.tx_hash, H256::from_low_u64_be(0xbeef));
        assert_eq!(alert.suspicion_score, 0.8);
        assert!(alert.summary.contains("Pre-filter alert (RPC)"));
        assert!(alert.summary.contains("self-destruct"));
    }

    #[test]
    fn test_build_deep_alert_fields() {
        let rpc_block = make_rpc_block(100);
        let suspicion = SuspiciousTx {
            tx_hash: H256::from_low_u64_be(0xcafe),
            tx_index: 1,
            reasons: vec![SuspicionReason::MultipleErc20Transfers { count: 10 }],
            score: 0.75,
            priority: AlertPriority::High,
        };

        let alert = build_deep_alert(&rpc_block, &suspicion, 5000, true);
        assert_eq!(alert.block_number, 100);
        assert_eq!(alert.total_steps, 5000);
        assert!(alert.summary.contains("Deep RPC alert"));
        assert!(alert.summary.contains("steps=5000"));
        assert!(alert.summary.contains("success=true"));
        assert!(alert.summary.contains("erc20-transfers"));
    }
}
