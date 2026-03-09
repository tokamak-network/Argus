//! RPC-mode Sentinel service — runs the full detection pipeline using any JSON-RPC endpoint.
//!
//! Like a security guard watching a live camera feed (RPC poller) instead of reviewing
//! footage from an internal hard drive (local Store). Same guard, same skills — different
//! data source. Supports two modes:
//!
//! - **prefilter_only = false** (default): Deep RPC replay. Requires an archive node.
//! - **prefilter_only = true**: Receipt heuristics only. Works with any full node.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};

use super::metrics::SentinelMetrics;
use super::pre_filter::PreFilter;
use super::rpc_poller::{RpcBlockPoller, RpcPollerConfig};
use super::rpc_replay::replay_tx_from_rpc;
use super::rpc_types::{rpc_block_to_ethrex, rpc_receipt_to_ethrex_typed};
use super::types::{
    AlertPriority, AnalysisConfig, SentinelAlert, SentinelConfig, SuspicionReason, SuspiciousTx,
};
use super::whitelist::WhitelistEngine;
use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::fund_flow::FundFlowTracer;
use crate::autopsy::rpc_client::{RpcBlock, RpcReceipt};
use crate::sentinel::analyzer::compute_total_value;
use crate::types::StepRecord;

/// Configuration for the RPC-mode sentinel service.
#[derive(Debug, Clone)]
pub struct RpcSentinelConfig {
    /// Ethereum RPC endpoint URL (used for block polling and receipt fetching).
    pub rpc_url: String,
    /// Optional separate archive RPC URL for deep opcode replay.
    /// When `None`, falls back to `rpc_url`. Use this to keep polling on a free
    /// public node while routing expensive replay queries to an archive endpoint.
    pub archive_rpc_url: Option<String>,
    /// Block poller configuration (poll interval, timeouts, retries).
    pub poller_config: RpcPollerConfig,
    /// Deep analysis configuration (step limits, confidence thresholds).
    pub analysis_config: AnalysisConfig,
    /// When true, skip deep RPC replay and emit alerts from pre-filter results only.
    /// Use this with standard full nodes that don't have archive state.
    pub prefilter_only: bool,
    /// Pre-filter heuristic thresholds (suspicion threshold, min ERC-20 transfers, etc.).
    /// When `None`, uses `SentinelConfig::default()`.
    pub prefilter_config: Option<SentinelConfig>,
    /// DeFi protocol whitelist engine for false-positive reduction.
    /// When `None`, no whitelist is applied.
    pub whitelist: Option<WhitelistEngine>,
    /// AI agent configuration. When `Some` and `enabled = true`, alerts are enriched
    /// with AI verdicts (2-pass: rule-based immediate → AI enrichment).
    #[cfg(feature = "ai_agent")]
    pub ai_config: Option<super::ai::AiConfig>,
}

impl RpcSentinelConfig {
    /// Create a config with sensible defaults for the given RPC URL.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        let rpc_url = rpc_url.into();
        let poller_config = RpcPollerConfig::new(rpc_url.clone());
        Self {
            rpc_url,
            archive_rpc_url: None,
            poller_config,
            analysis_config: AnalysisConfig {
                prefilter_alert_mode: true, // emit alerts even without deep analysis
                ..Default::default()
            },
            prefilter_only: false,
            prefilter_config: None,
            whitelist: None,
            #[cfg(feature = "ai_agent")]
            ai_config: None,
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
    // AI judge setup (only when ai_agent feature is enabled) — must happen
    // before `config.poller_config` is moved into the poller.
    #[cfg(feature = "ai_agent")]
    let ai_judge = super::rpc_ai::init_ai_judge(config.ai_config.as_ref());

    let poller = RpcBlockPoller::new(config.poller_config);
    let mut block_rx = poller.start().await;

    let sentinel_config = config.prefilter_config.clone().unwrap_or_default();
    let pre_filter = match config.whitelist.clone() {
        Some(engine) => PreFilter::with_whitelist(sentinel_config, engine),
        None => PreFilter::new(sentinel_config),
    };
    // Use archive_rpc_url for deep replay if provided, otherwise fall back to rpc_url
    let replay_rpc_url = config
        .archive_rpc_url
        .clone()
        .unwrap_or_else(|| config.rpc_url.clone());
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
                        rpc_url: &replay_rpc_url,
                        analysis_config: &analysis_config,
                        prefilter_only,
                        alert_tx: &alert_tx,
                        metrics: &metrics,
                        #[cfg(feature = "ai_agent")]
                        ai_judge: ai_judge.as_ref(),
                    },
                )
                .await;
            }
        }
    }
}

/// Shared processing context passed to `process_rpc_block`.
pub(crate) struct ProcessContext<'a> {
    pre_filter: &'a PreFilter,
    rpc_url: &'a str,
    analysis_config: &'a AnalysisConfig,
    prefilter_only: bool,
    alert_tx: &'a mpsc::Sender<SentinelAlert>,
    metrics: &'a SentinelMetrics,
    #[cfg(feature = "ai_agent")]
    ai_judge: Option<&'a super::ai::judge::AiJudge<super::ai::LiteLLMClient>>,
}

#[cfg(test)]
impl<'a> ProcessContext<'a> {
    pub(crate) fn new_for_test(
        pre_filter: &'a PreFilter,
        rpc_url: &'a str,
        analysis_config: &'a AnalysisConfig,
        prefilter_only: bool,
        alert_tx: &'a mpsc::Sender<SentinelAlert>,
        metrics: &'a SentinelMetrics,
    ) -> Self {
        Self {
            pre_filter,
            rpc_url,
            analysis_config,
            prefilter_only,
            alert_tx,
            metrics,
            #[cfg(feature = "ai_agent")]
            ai_judge: None,
        }
    }
}

/// Process one `(RpcBlock, Vec<RpcReceipt>)` pair through the detection pipeline.
pub(crate) async fn process_rpc_block(
    rpc_block: &RpcBlock,
    rpc_receipts: &[RpcReceipt],
    ctx: ProcessContext<'_>,
) {
    let pre_filter = ctx.pre_filter;
    let rpc_url = ctx.rpc_url;
    let analysis_config = ctx.analysis_config;
    let prefilter_only = ctx.prefilter_only;
    let alert_tx = ctx.alert_tx;
    let metrics = ctx.metrics;
    // Convert RPC types to ethrex types for pre-filter
    let ethrex_block = match rpc_block_to_ethrex(rpc_block) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[rpc_sentinel] block type conversion failed: {e}");
            return;
        }
    };
    let ethrex_receipts: Vec<_> = rpc_receipts
        .iter()
        .zip(rpc_block.transactions.iter())
        .map(|(receipt, tx)| rpc_receipt_to_ethrex_typed(receipt, tx))
        .collect();

    metrics.increment_blocks_scanned();
    metrics.increment_txs_scanned(ethrex_block.body.transactions.len() as u64);

    // Stage 1: Pre-filter (receipt-based heuristics)
    let prefilter_start = Instant::now();
    let mut suspicious_txs = pre_filter.scan_block(
        &ethrex_block.body.transactions,
        &ethrex_receipts,
        &ethrex_block.header,
    );
    let prefilter_us = prefilter_start.elapsed().as_micros() as u64;

    // Fix TX hashes: ethrex recomputes hash from RLP (missing v/r/s signatures),
    // so we overwrite with the original hash from the RPC response.
    for suspicion in &mut suspicious_txs {
        if let Some(rpc_tx) = rpc_block.transactions.get(suspicion.tx_index) {
            suspicion.tx_hash = rpc_tx.hash;
        }
    }
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
                // Deep analysis succeeded — build enriched alert with classifier + fund flow
                let alert = build_deep_alert(
                    rpc_block,
                    suspicion,
                    &replay.trace.steps,
                    replay.trace.success,
                );

                // AI enrichment: extract context from steps and run AI judge (2nd pass)
                #[cfg(feature = "ai_agent")]
                if let Some(judge) = ctx.ai_judge {
                    let verdict = super::rpc_ai::enrich_with_ai(
                        judge,
                        &replay.trace.steps,
                        rpc_block,
                        suspicion,
                        replay.trace.success,
                    )
                    .await;
                    let mut enriched = alert;
                    enriched.agent_verdict = verdict;
                    enriched
                } else {
                    alert
                }
                #[cfg(not(feature = "ai_agent"))]
                alert
            }
            Err(_) if prefilter_alert_mode => {
                // Deep analysis failed but prefilter_alert_mode is on
                let mut alert = build_prefilter_alert(rpc_block, suspicion);
                alert.data_quality = Some(crate::types::DataQuality::Low);
                alert
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
        SuspicionReason::AsymmetricCashFlow { .. } => "asymmetric-cash-flow",
    }
}

fn build_alert_base(rpc_block: &RpcBlock, suspicion: &SuspiciousTx) -> SentinelAlert {
    SentinelAlert {
        block_number: rpc_block.header.number,
        block_hash: rpc_block.header.hash,
        tx_hash: suspicion.tx_hash,
        tx_index: suspicion.tx_index,
        alert_priority: AlertPriority::from_score(suspicion.score),
        suspicion_reasons: suspicion.reasons.clone(),
        suspicion_score: suspicion.score,
        detected_patterns: vec![],
        fund_flows: vec![],
        total_value_at_risk: ethrex_common::U256::zero(),
        whitelist_matches: suspicion.whitelist_matches,
        summary: String::new(),
        total_steps: 0,
        data_quality: None,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    }
}

pub(crate) fn build_prefilter_alert(
    rpc_block: &RpcBlock,
    suspicion: &SuspiciousTx,
) -> SentinelAlert {
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

/// Build an enriched `SentinelAlert` after RPC replay (classifier + fund flow).
pub(crate) fn build_deep_alert(
    rpc_block: &RpcBlock,
    suspicion: &SuspiciousTx,
    steps: &[StepRecord],
    success: bool,
) -> SentinelAlert {
    let total_steps = steps.len();
    let detected_patterns = AttackClassifier::classify_with_confidence(steps);
    let fund_flows = FundFlowTracer::trace(steps);
    let total_value_at_risk = compute_total_value(&fund_flows);

    let reason_names: Vec<&str> = suspicion.reasons.iter().map(reason_display_name).collect();
    let summary = format!(
        "Deep RPC alert: {} (score={:.2}, steps={total_steps}, success={success})",
        reason_names.join(", "),
        suspicion.score
    );
    SentinelAlert {
        summary,
        total_steps,
        detected_patterns,
        fund_flows,
        total_value_at_risk,
        data_quality: Some(crate::types::DataQuality::High),
        ..build_alert_base(rpc_block, suspicion)
    }
}
