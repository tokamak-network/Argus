//! Sentinel background service for block monitoring.
//!
//! `SentinelService` runs a dedicated background thread that receives committed
//! blocks via a channel, applies the pre-filter heuristics, and deep-analyzes
//! any suspicious transactions using the Autopsy Lab pipeline.
//!
//! The service implements `ethrex_blockchain::BlockObserver` so it can be plugged
//! directly into the `Blockchain` struct without creating a circular dependency.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use ethrex_blockchain::{BlockObserver, MempoolObserver};
use ethrex_common::types::{Block, Receipt, Transaction};
use ethrex_common::{Address, H256};
use ethrex_storage::Store;

use super::config::MempoolMonitorConfig;
use super::mempool_filter::MempoolPreFilter;

use super::analyzer::DeepAnalyzer;
use super::metrics::SentinelMetrics;
use super::pre_filter::PreFilter;
use super::types::{AlertPriority, AnalysisConfig, SentinelAlert, SentinelConfig, SuspiciousTx};

use super::types::MempoolAlert;

/// Message sent from the block processing pipeline to the sentinel worker.
enum SentinelMessage {
    /// A new block has been committed to the store.
    BlockCommitted {
        block: Box<Block>,
        receipts: Vec<Receipt>,
    },
    /// A pending mempool TX was flagged as suspicious.
    MempoolFlagged { alert: MempoolAlert },
    /// Graceful shutdown request.
    Shutdown,
}

/// Callback trait for consuming alerts produced by the sentinel.
///
/// Implementations might log to stderr, write to a JSONL file, or POST to a webhook.
pub trait AlertHandler: Send + 'static {
    fn on_alert(&self, alert: SentinelAlert);
}

/// Default alert handler that logs to stderr.
pub struct LogAlertHandler;

impl AlertHandler for LogAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        eprintln!(
            "[SENTINEL ALERT] block={} tx_index={} priority={:?} summary={}",
            alert.block_number, alert.tx_index, alert.alert_priority, alert.summary
        );
    }
}

/// Background sentinel service that monitors committed blocks for suspicious activity.
///
/// The service uses a single background thread connected via an `mpsc` channel.
/// `on_block_committed()` is non-blocking: it sends block data to the channel
/// and returns immediately, ensuring zero overhead on the block processing hot path.
///
/// The worker thread runs the two-stage pipeline:
/// 1. **Pre-filter** (receipt-based heuristics, ~10-50μs per TX)
/// 2. **Deep analysis** (opcode replay + attack classification, only for suspicious TXs)
pub struct SentinelService {
    sender: Mutex<mpsc::Sender<SentinelMessage>>,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
    metrics: Arc<SentinelMetrics>,
    /// Stateless mempool pre-filter (Send + Sync, no Mutex needed).
    mempool_filter: Option<MempoolPreFilter>,
}

impl SentinelService {
    /// Create a new sentinel service with a background worker thread.
    ///
    /// The `store` is used by the deep analyzer to replay suspicious transactions.
    /// The `alert_handler` receives confirmed alerts.
    pub fn new(
        store: Store,
        config: SentinelConfig,
        analysis_config: AnalysisConfig,
        alert_handler: Box<dyn AlertHandler>,
    ) -> Self {
        Self::with_mempool(store, config, analysis_config, alert_handler, None)
    }

    /// Create a sentinel service with optional mempool monitoring.
    pub fn with_mempool(
        store: Store,
        config: SentinelConfig,
        analysis_config: AnalysisConfig,
        alert_handler: Box<dyn AlertHandler>,
        mempool_config: Option<MempoolMonitorConfig>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let metrics = Arc::new(SentinelMetrics::new());
        let worker_metrics = metrics.clone();

        let worker_handle = thread::Builder::new()
            .name("sentinel-worker".to_string())
            .spawn(move || {
                Self::worker_loop(
                    receiver,
                    store,
                    config,
                    analysis_config,
                    alert_handler,
                    worker_metrics,
                );
            })
            .expect("Failed to spawn sentinel worker thread");

        let mempool_filter =
            mempool_config.map(|cfg| MempoolPreFilter::new(&cfg));

        Self {
            sender: Mutex::new(sender),
            worker_handle: Mutex::new(Some(worker_handle)),
            metrics,
            mempool_filter,
        }
    }

    /// Returns a shared reference to the pipeline metrics.
    pub fn metrics(&self) -> Arc<SentinelMetrics> {
        self.metrics.clone()
    }

    /// Request graceful shutdown of the background worker.
    pub fn shutdown(&self) {
        if let Ok(sender) = self.sender.lock() {
            let _ = sender.send(SentinelMessage::Shutdown);
        }
    }

    /// Returns true if the background worker thread is still alive.
    pub fn is_running(&self) -> bool {
        self.worker_handle
            .lock()
            .map(|h| h.as_ref().is_some_and(|jh| !jh.is_finished()))
            .unwrap_or(false)
    }

    fn worker_loop(
        receiver: mpsc::Receiver<SentinelMessage>,
        store: Store,
        config: SentinelConfig,
        analysis_config: AnalysisConfig,
        alert_handler: Box<dyn AlertHandler>,
        metrics: Arc<SentinelMetrics>,
    ) {
        let pre_filter = PreFilter::new(config);
        let pipeline = super::pipeline::AnalysisPipeline::default_pipeline();

        while let Ok(msg) = receiver.recv() {
            match msg {
                SentinelMessage::BlockCommitted { block, receipts } => {
                    Self::process_block(
                        &store,
                        &block,
                        &receipts,
                        &pre_filter,
                        &analysis_config,
                        &*alert_handler,
                        &metrics,
                        &pipeline,
                    );
                }
                SentinelMessage::MempoolFlagged { alert } => {
                    metrics.increment_mempool_alerts_emitted();
                    // Convert MempoolAlert to a lightweight SentinelAlert for the handler pipeline
                    let sentinel_alert = SentinelAlert {
                        block_number: 0, // pending — not yet in a block
                        block_hash: ethrex_common::H256::zero(),
                        tx_hash: alert.tx_hash,
                        tx_index: 0,
                        alert_priority: AlertPriority::from_score(alert.score),
                        suspicion_reasons: vec![],
                        suspicion_score: alert.score,
                        #[cfg(feature = "autopsy")]
                        detected_patterns: vec![],
                        #[cfg(feature = "autopsy")]
                        fund_flows: vec![],
                        total_value_at_risk: ethrex_common::U256::zero(),
                        summary: format!(
                            "Mempool alert: {} reasons (score={:.2})",
                            alert.reasons.len(),
                            alert.score
                        ),
                        total_steps: 0,
                        feature_vector: None,
                    };
                    alert_handler.on_alert(sentinel_alert);
                }
                SentinelMessage::Shutdown => break,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_block(
        store: &Store,
        block: &Block,
        receipts: &[Receipt],
        pre_filter: &PreFilter,
        analysis_config: &AnalysisConfig,
        alert_handler: &dyn AlertHandler,
        metrics: &SentinelMetrics,
        pipeline: &super::pipeline::AnalysisPipeline,
    ) {
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(block.body.transactions.len() as u64);

        // Stage 1: Pre-filter with lightweight receipt-based heuristics
        let prefilter_start = Instant::now();
        let suspicious_txs =
            pre_filter.scan_block(&block.body.transactions, receipts, &block.header);
        let prefilter_us = prefilter_start.elapsed().as_micros() as u64;
        metrics.add_prefilter_us(prefilter_us);

        metrics.increment_txs_flagged(suspicious_txs.len() as u64);

        if suspicious_txs.is_empty() {
            return;
        }

        // Stage 2: Deep analysis for each suspicious TX
        for suspicion in &suspicious_txs {
            let analysis_start = Instant::now();
            match DeepAnalyzer::analyze(store, block, suspicion, analysis_config, Some(pipeline)) {
                Ok(Some(alert)) => {
                    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
                    metrics.add_deep_analysis_ms(analysis_ms);
                    metrics.increment_alerts_emitted();
                    alert_handler.on_alert(alert);
                }
                Ok(None) if analysis_config.prefilter_alert_mode => {
                    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
                    metrics.add_deep_analysis_ms(analysis_ms);
                    metrics.increment_alerts_emitted();
                    alert_handler.on_alert(Self::build_prefilter_alert(block, suspicion));
                }
                Ok(None) => {
                    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
                    metrics.add_deep_analysis_ms(analysis_ms);
                }
                Err(_e) if analysis_config.prefilter_alert_mode => {
                    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
                    metrics.add_deep_analysis_ms(analysis_ms);
                    metrics.increment_alerts_emitted();
                    alert_handler.on_alert(Self::build_prefilter_alert(block, suspicion));
                }
                Err(_e) => {
                    let analysis_ms = analysis_start.elapsed().as_millis() as u64;
                    metrics.add_deep_analysis_ms(analysis_ms);
                }
            }
        }
    }

    /// Build a lightweight alert from pre-filter results when deep analysis
    /// is unavailable (no Merkle trie state) or dismissed the suspicion.
    fn build_prefilter_alert(block: &Block, suspicion: &SuspiciousTx) -> SentinelAlert {
        let reason_names: Vec<&str> = suspicion
            .reasons
            .iter()
            .map(|r| match r {
                super::types::SuspicionReason::FlashLoanSignature { .. } => "flash-loan",
                super::types::SuspicionReason::HighValueWithRevert { .. } => "high-value-revert",
                super::types::SuspicionReason::MultipleErc20Transfers { .. } => "erc20-transfers",
                super::types::SuspicionReason::KnownContractInteraction { .. } => "known-contract",
                super::types::SuspicionReason::UnusualGasPattern { .. } => "unusual-gas",
                super::types::SuspicionReason::SelfDestructDetected => "self-destruct",
                super::types::SuspicionReason::PriceOracleWithSwap { .. } => "oracle-swap",
            })
            .collect();

        SentinelAlert {
            block_number: block.header.number,
            block_hash: block.header.compute_block_hash(),
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
            summary: format!(
                "Pre-filter alert: {} (score={:.2})",
                reason_names.join(", "),
                suspicion.score
            ),
            total_steps: 0,
            feature_vector: None,
        }
    }
}

impl MempoolObserver for SentinelService {
    fn on_transaction_added(&self, tx: &Transaction, sender: Address, tx_hash: H256) {
        self.metrics.increment_mempool_txs_scanned();

        let Some(ref filter) = self.mempool_filter else {
            return;
        };

        if let Some(alert) = filter.scan_transaction(tx, sender, tx_hash) {
            self.metrics.increment_mempool_txs_flagged();
            if let Ok(sender_lock) = self.sender.lock() {
                let _ = sender_lock.send(SentinelMessage::MempoolFlagged { alert });
            }
        }
    }
}

impl BlockObserver for SentinelService {
    fn on_block_committed(&self, block: Block, receipts: Vec<Receipt>) {
        if let Ok(sender) = self.sender.lock() {
            // Non-blocking send — if channel is disconnected, silently drop
            let _ = sender.send(SentinelMessage::BlockCommitted {
                block: Box::new(block),
                receipts,
            });
        }
    }
}

impl Drop for SentinelService {
    fn drop(&mut self) {
        self.shutdown();
        if let Ok(mut handle) = self.worker_handle.lock()
            && let Some(h) = handle.take()
        {
            let _ = h.join();
        }
    }
}
