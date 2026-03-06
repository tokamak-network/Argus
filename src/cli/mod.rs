//! CLI entry point for the argus binary.

pub mod commands;
pub mod formatter;
pub mod repl;

use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use ethrex_common::{
    Address, U256,
    constants::EMPTY_TRIE_HASH,
    types::{Account, BlockHeader, Code, EIP1559Transaction, Transaction, TxKind},
};
use ethrex_levm::{Environment, db::gen_db::GeneralizedDatabase};
use rustc_hash::FxHashMap;

use crate::engine::ReplayEngine;
use crate::error::DebuggerError;
use crate::types::ReplayConfig;

/// Tokamak EVM time-travel debugger.
#[derive(Parser)]
#[command(
    name = "argus",
    about = "Ethereum attack detection and forensics toolkit"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: InputMode,
}

/// Input mode for the debugger.
#[derive(Subcommand)]
pub enum InputMode {
    /// Debug raw EVM bytecode
    #[command(name = "bytecode")]
    Bytecode {
        /// Hex-encoded bytecode (with or without 0x prefix)
        #[arg(long)]
        code: String,

        /// Gas limit for execution
        #[arg(long, default_value = "9223372036854775806")]
        gas_limit: u64,
    },

    /// Analyze a historical transaction (Smart Contract Autopsy Lab)
    #[cfg(feature = "autopsy")]
    #[command(name = "autopsy")]
    Autopsy {
        /// Transaction hash to analyze
        #[arg(long = "tx-hash", alias = "tx", short = 't')]
        tx_hash: String,

        /// Ethereum archive node RPC URL
        #[arg(long = "rpc-url", alias = "rpc", short = 'r')]
        rpc_url: String,

        /// Block number (auto-detected from tx if omitted)
        #[arg(long)]
        block_number: Option<u64>,

        /// Output format: json or markdown
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Output file path (default: autopsy-<tx_hash_prefix>.<ext> in current dir)
        #[arg(long, short)]
        output: Option<String>,

        /// RPC request timeout in seconds (default: 30)
        #[arg(long, default_value = "30")]
        rpc_timeout: u64,

        /// Maximum RPC retry attempts for transient errors (default: 3)
        #[arg(long, default_value = "3")]
        rpc_retries: u32,

        /// Suppress metrics output (default: false)
        #[arg(long, default_value = "false")]
        quiet: bool,

        /// After autopsy analysis, drop into the GDB-style debugger REPL
        #[arg(long, short = 'i', default_value = "false")]
        interactive: bool,
    },

    /// Monitor Ethereum in real time via JSON-RPC (no local node required)
    #[cfg(all(feature = "sentinel", feature = "autopsy"))]
    #[command(name = "sentinel")]
    Sentinel {
        /// Ethereum RPC endpoint URL for block polling (e.g. https://eth.llamarpc.com)
        #[arg(long = "rpc-url", alias = "rpc", short = 'r')]
        rpc_url: String,

        /// Optional archive RPC URL for deep opcode replay (e.g. Alchemy).
        /// If not set, uses --rpc for both polling and replay.
        #[arg(long = "archive-rpc")]
        archive_rpc_url: Option<String>,

        /// Optional TOML config file path (overridden by CLI flags)
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// Append alerts as JSON lines to this file
        #[arg(long = "alert-file")]
        alert_file: Option<PathBuf>,

        /// Skip deep opcode replay — pre-filter heuristics only (works with any full node)
        #[arg(long, default_value = "false")]
        prefilter_only: bool,

        /// Port for HTTP metrics/health server
        #[arg(long, default_value = "9090")]
        metrics_port: u16,

        /// Webhook URL for HTTP POST alert notifications
        #[arg(long)]
        webhook_url: Option<String>,

        /// Block polling interval in seconds
        #[arg(long, default_value = "2")]
        poll_interval: u64,

        /// Enable AI-assisted attack classification (requires LITELLM_API_KEY env var)
        #[cfg(feature = "ai_agent")]
        #[arg(long = "ai", default_value = "false")]
        ai_enabled: bool,
    },
}

/// Run the debugger CLI.
pub fn run(args: Args) -> Result<(), DebuggerError> {
    match args.command {
        InputMode::Bytecode { code, gas_limit } => run_bytecode(&code, gas_limit),
        #[cfg(feature = "autopsy")]
        InputMode::Autopsy {
            tx_hash,
            rpc_url,
            block_number,
            format,
            output,
            rpc_timeout,
            rpc_retries,
            quiet,
            interactive,
        } => run_autopsy(
            &tx_hash,
            &rpc_url,
            block_number,
            &format,
            output.as_deref(),
            rpc_timeout,
            rpc_retries,
            quiet,
            interactive,
        ),
        #[cfg(all(feature = "sentinel", feature = "autopsy"))]
        InputMode::Sentinel {
            rpc_url,
            archive_rpc_url,
            config,
            alert_file,
            prefilter_only,
            metrics_port,
            webhook_url,
            poll_interval,
            #[cfg(feature = "ai_agent")]
            ai_enabled,
        } => run_sentinel(
            &rpc_url,
            archive_rpc_url,
            config,
            alert_file,
            prefilter_only,
            metrics_port,
            webhook_url,
            poll_interval,
            #[cfg(feature = "ai_agent")]
            ai_enabled,
        ),
    }
}

const CONTRACT_ADDR: u64 = 0x42;
const SENDER_ADDR: u64 = 0x100;

fn run_bytecode(code_hex: &str, gas_limit: u64) -> Result<(), DebuggerError> {
    let hex_str = code_hex.strip_prefix("0x").unwrap_or(code_hex);
    let bytecode =
        hex::decode(hex_str).map_err(|e| DebuggerError::InvalidBytecode(e.to_string()))?;

    let contract_addr = Address::from_low_u64_be(CONTRACT_ADDR);
    let sender_addr = Address::from_low_u64_be(SENDER_ADDR);

    let mut db = make_cli_db(contract_addr, sender_addr, bytecode)?;
    let env = Environment {
        origin: sender_addr,
        gas_limit,
        block_gas_limit: gas_limit,
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(contract_addr),
        data: Bytes::new(),
        ..Default::default()
    });

    let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())?;

    println!("Recorded {} steps. Starting debugger...\n", engine.len());

    repl::start(engine)
}

fn make_cli_db(
    contract_addr: Address,
    sender_addr: Address,
    bytecode: Vec<u8>,
) -> Result<GeneralizedDatabase, DebuggerError> {
    let store = ethrex_storage::Store::new("", ethrex_storage::EngineType::InMemory)
        .map_err(|e| DebuggerError::Cli(format!("Failed to create store: {e}")))?;
    let header = BlockHeader {
        state_root: *EMPTY_TRIE_HASH,
        ..Default::default()
    };
    let vm_db: ethrex_vm::DynVmDatabase = Box::new(
        ethrex_blockchain::vm::StoreVmDatabase::new(store, header)
            .map_err(|e| DebuggerError::Cli(format!("Failed to create VM database: {e}")))?,
    );

    let mut cache = FxHashMap::default();
    cache.insert(
        contract_addr,
        Account::new(
            U256::zero(),
            Code::from_bytecode(Bytes::from(bytecode)),
            0,
            FxHashMap::default(),
        ),
    );
    cache.insert(
        sender_addr,
        Account::new(
            U256::MAX,
            Code::from_bytecode(Bytes::new()),
            0,
            FxHashMap::default(),
        ),
    );

    Ok(GeneralizedDatabase::new_with_account_state(
        Arc::new(vm_db),
        cache,
    ))
}

// ---------------------------------------------------------------------------
// Autopsy helper functions
// ---------------------------------------------------------------------------

/// Parse a hex-encoded transaction hash string into an H256.
#[cfg(feature = "autopsy")]
pub fn parse_tx_hash(tx_hash_hex: &str) -> Result<ethrex_common::H256, DebuggerError> {
    let hash_hex = tx_hash_hex.strip_prefix("0x").unwrap_or(tx_hash_hex);
    if !hash_hex.len().is_multiple_of(2) {
        return Err(crate::error::RpcError::simple("tx hash hex must have even length").into());
    }
    let hash_bytes: Vec<u8> = (0..hash_hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hash_hex[i..i + 2], 16).map_err(|e| {
                DebuggerError::Rpc(crate::error::RpcError::simple(format!(
                    "invalid tx hash: {e}"
                )))
            })
        })
        .collect::<Result<_, _>>()?;
    if hash_bytes.len() != 32 {
        return Err(crate::error::RpcError::simple("tx hash must be 32 bytes").into());
    }
    Ok(ethrex_common::H256::from_slice(&hash_bytes))
}

/// Fetch a transaction by hash and determine its block number.
#[cfg(feature = "autopsy")]
fn fetch_tx_and_block(
    rpc_url: &str,
    tx_hash: ethrex_common::H256,
    block_number_override: Option<u64>,
    rpc_config: &crate::autopsy::rpc_client::RpcConfig,
) -> Result<(crate::autopsy::rpc_client::RpcTransaction, u64), DebuggerError> {
    let temp_client =
        crate::autopsy::rpc_client::EthRpcClient::with_config(rpc_url, 0, rpc_config.clone());
    let rpc_tx = temp_client
        .eth_get_transaction_by_hash(tx_hash)
        .map_err(|e| {
            DebuggerError::Rpc(crate::error::RpcError::simple(format!("fetch tx: {e}")))
        })?;
    let block_num = block_number_override
        .or(rpc_tx.block_number)
        .ok_or_else(|| {
            DebuggerError::Rpc(crate::error::RpcError::simple(
                "could not determine block number — provide --block-number",
            ))
        })?;
    Ok((rpc_tx, block_num))
}

/// Create a remote VM database and build the EVM environment + transaction.
#[cfg(feature = "autopsy")]
fn setup_replay(
    rpc_url: &str,
    block_num: u64,
    rpc_tx: &crate::autopsy::rpc_client::RpcTransaction,
    rpc_config: &crate::autopsy::rpc_client::RpcConfig,
) -> Result<
    (
        GeneralizedDatabase,
        Environment,
        Transaction,
        u64, // pre_block
    ),
    DebuggerError,
> {
    use crate::autopsy::remote_db::RemoteVmDatabase;

    let pre_block = block_num.saturating_sub(1);
    let remote_db = RemoteVmDatabase::from_rpc_with_config(rpc_url, pre_block, rpc_config.clone())
        .map_err(|e| {
            DebuggerError::Rpc(crate::error::RpcError::simple(format!("remote db: {e}")))
        })?;

    let client = remote_db.client();
    let block_header = client.eth_get_block_by_number(block_num).map_err(|e| {
        DebuggerError::Rpc(crate::error::RpcError::simple(format!("fetch block: {e}")))
    })?;

    let env = crate::autopsy::rpc_types::build_env_from_rpc(rpc_tx, &block_header);
    let tx = crate::autopsy::rpc_types::rpc_tx_to_ethrex(rpc_tx);

    let db = GeneralizedDatabase::new(Arc::new(remote_db));
    Ok((db, env, tx, pre_block))
}

/// Parameters for post-replay analysis and report generation.
#[cfg(feature = "autopsy")]
struct AnalysisContext<'a> {
    rpc_url: &'a str,
    pre_block: u64,
    rpc_config: crate::autopsy::rpc_client::RpcConfig,
    tx_hash: ethrex_common::H256,
    tx_hash_hex: &'a str,
    block_num: u64,
    output_format: &'a str,
    output_path: Option<&'a str>,
}

/// Analyze a replayed trace: classify attacks, trace funds, enrich storage, and write report.
///
/// Takes ownership of the `ReplayTrace` to avoid unnecessary cloning.
/// Callers should clone the trace before calling this if they need it afterward.
#[cfg(feature = "autopsy")]
fn analyze_and_report(mut trace: crate::types::ReplayTrace, ctx: &AnalysisContext) -> Result<(), DebuggerError> {
    use crate::autopsy::{
        classifier::AttackClassifier,
        enrichment::{collect_sstore_slots, enrich_storage_writes},
        fund_flow::FundFlowTracer,
        report::AutopsyReport,
        rpc_client::EthRpcClient,
    };
    let slots = collect_sstore_slots(&trace.steps);
    let mut initial_values = rustc_hash::FxHashMap::default();

    let pre_client = EthRpcClient::with_config(ctx.rpc_url, ctx.pre_block, ctx.rpc_config.clone());
    for (addr, slot) in &slots {
        if let Ok(val) = pre_client.eth_get_storage_at(*addr, *slot) {
            initial_values.insert((*addr, *slot), val);
        }
    }
    enrich_storage_writes(&mut trace, &initial_values);

    let patterns = AttackClassifier::classify(&trace.steps);
    let flows = FundFlowTracer::trace(&trace.steps);

    let storage_diffs: Vec<_> = trace
        .steps
        .iter()
        .filter_map(|s| s.storage_writes.as_ref())
        .flatten()
        .cloned()
        .collect();

    let report = AutopsyReport::build(
        ctx.tx_hash,
        ctx.block_num,
        &trace.steps,
        patterns.clone(),
        flows.clone(),
        storage_diffs,
    );

    let summary = formatter::format_autopsy_summary(
        &patterns,
        &flows,
        &trace,
        ctx.tx_hash_hex,
        ctx.block_num,
    );
    eprintln!("{summary}");

    let (content, ext) = match ctx.output_format {
        "json" => {
            let json = report
                .to_json()
                .map_err(|e| DebuggerError::Report(format!("JSON serialization: {e}")))?;
            (json, "json")
        }
        _ => (report.to_markdown(), "md"),
    };

    let file_path = match ctx.output_path {
        Some(p) => p.to_string(),
        None => {
            let hash_prefix = ctx
                .tx_hash_hex
                .strip_prefix("0x")
                .unwrap_or(ctx.tx_hash_hex)
                .get(..8)
                .unwrap_or("unknown");
            format!("autopsy-{hash_prefix}.{ext}")
        }
    };

    std::fs::write(&file_path, &content)
        .map_err(|e| DebuggerError::Report(format!("write {file_path}: {e}")))?;

    eprintln!("[autopsy] Report saved to {file_path}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Autopsy orchestrator
// ---------------------------------------------------------------------------

#[cfg(feature = "autopsy")]
#[allow(clippy::too_many_arguments)]
fn run_autopsy(
    tx_hash_hex: &str,
    rpc_url: &str,
    block_number_override: Option<u64>,
    output_format: &str,
    output_path: Option<&str>,
    rpc_timeout: u64,
    rpc_retries: u32,
    _quiet: bool,
    interactive: bool,
) -> Result<(), DebuggerError> {
    use std::time::Duration;

    use crate::autopsy::rpc_client::RpcConfig;

    let rpc_config = RpcConfig {
        timeout: Duration::from_secs(rpc_timeout),
        max_retries: rpc_retries,
        ..RpcConfig::default()
    };

    eprintln!("[autopsy] Fetching transaction...");
    let tx_hash = parse_tx_hash(tx_hash_hex)?;
    let (rpc_tx, block_num) =
        fetch_tx_and_block(rpc_url, tx_hash, block_number_override, &rpc_config)?;

    eprintln!("[autopsy] Block #{block_num}, setting up remote database...");
    let (mut db, env, tx, pre_block) = setup_replay(rpc_url, block_num, &rpc_tx, &rpc_config)?;

    eprintln!("[autopsy] Replaying transaction...");
    let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())?;
    eprintln!("[autopsy] Recorded {} steps. Analyzing...", engine.len());

    let ctx = AnalysisContext {
        rpc_url,
        pre_block,
        rpc_config,
        tx_hash,
        tx_hash_hex,
        block_num,
        output_format,
        output_path,
    };

    if interactive {
        // Clone trace for analysis; keep engine intact for the REPL.
        let trace = engine.trace().clone();
        analyze_and_report(trace, &ctx)?;
        eprintln!("[autopsy] Entering interactive debugger...");
        repl::start(engine)?;
    } else {
        // Consume engine — no clone needed.
        let trace = engine.into_trace();
        analyze_and_report(trace, &ctx)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sentinel subcommand
// ---------------------------------------------------------------------------

#[cfg(all(feature = "sentinel", feature = "autopsy"))]
#[allow(clippy::too_many_arguments)]
fn run_sentinel(
    rpc_url: &str,
    archive_rpc_url: Option<String>,
    config: Option<PathBuf>,
    alert_file: Option<PathBuf>,
    prefilter_only: bool,
    metrics_port: u16,
    webhook_url: Option<String>,
    poll_interval: u64,
    #[cfg(feature = "ai_agent")] ai_enabled: bool,
) -> Result<(), DebuggerError> {
    // Load TOML config (or defaults if no path given)
    let full_config = crate::sentinel::config::load_config(config.as_ref())
        .map_err(|e| DebuggerError::Cli(format!("Config error: {e}")))?;

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| DebuggerError::Cli(format!("Failed to create tokio runtime: {e}")))?;
    rt.block_on(run_sentinel_async(
        rpc_url,
        archive_rpc_url,
        alert_file,
        prefilter_only,
        metrics_port,
        webhook_url,
        poll_interval,
        full_config,
        #[cfg(feature = "ai_agent")]
        ai_enabled,
    ))
}

#[cfg(all(feature = "sentinel", feature = "autopsy"))]
#[allow(clippy::too_many_arguments)]
async fn run_sentinel_async(
    rpc_url: &str,
    archive_rpc_url: Option<String>,
    alert_file: Option<PathBuf>,
    prefilter_only: bool,
    metrics_port: u16,
    webhook_url: Option<String>,
    poll_interval: u64,
    full_config: crate::sentinel::config::SentinelFullConfig,
    #[cfg(feature = "ai_agent")] ai_enabled: bool,
) -> Result<(), DebuggerError> {
    use std::time::{Duration, Instant};

    use tokio::sync::mpsc;

    use crate::sentinel::{
        alert::{AlertDispatcher, JsonlFileAlertHandler, StdoutAlertHandler},
        rpc_poller::RpcPollerConfig,
        rpc_service::{RpcSentinelConfig, RpcSentinelService},
        service::AlertHandler,
        types::SentinelAlert,
    };

    let start_time = Instant::now();

    // Mask the URL for display (hide API keys embedded in paths)
    let masked_url = if rpc_url.len() > 40 {
        format!(
            "{}...{}",
            &rpc_url[..40],
            &rpc_url[rpc_url.len().saturating_sub(4)..]
        )
    } else {
        rpc_url.to_string()
    };
    eprintln!("[sentinel] Starting on {masked_url}");
    eprintln!(
        "[sentinel] prefilter_only={prefilter_only}  poll_interval={poll_interval}s  metrics_port={metrics_port}"
    );
    #[cfg(feature = "ai_agent")]
    if ai_enabled {
        eprintln!("[sentinel] AI agent enabled (2-tier: screening + deep analysis)");
    }
    eprintln!("[sentinel] Press Ctrl+C to stop.");

    // Build RpcSentinelConfig from loaded TOML config
    let analysis_config = full_config.to_analysis_config();
    let prefilter_config = full_config.to_sentinel_config();
    eprintln!(
        "[sentinel] config: suspicion_threshold={:.2}  min_erc20={} prefilter_alert_mode={} mev_flash={:.2} mev_selfdestruct={:.2}",
        prefilter_config.suspicion_threshold,
        prefilter_config.min_erc20_transfers,
        analysis_config.prefilter_alert_mode,
        prefilter_config.mev_flash_loan_factor,
        prefilter_config.mev_selfdestruct_factor,
    );
    if let Some(ref archive_url) = archive_rpc_url {
        let masked = if archive_url.len() > 40 {
            format!(
                "{}...{}",
                &archive_url[..40],
                &archive_url[archive_url.len().saturating_sub(4)..]
            )
        } else {
            archive_url.clone()
        };
        eprintln!("[sentinel] archive RPC (deep replay): {masked}");
    }
    // Build whitelist engine from TOML config
    let whitelist_engine = full_config.to_whitelist_engine();
    let wl_count = whitelist_engine.len();
    if wl_count > 0 {
        eprintln!("[sentinel] Loaded {wl_count} whitelist entries");
    }

    let sentinel_config = RpcSentinelConfig {
        rpc_url: rpc_url.to_string(),
        archive_rpc_url,
        poller_config: RpcPollerConfig {
            rpc_url: rpc_url.to_string(),
            poll_interval: Duration::from_secs(poll_interval),
            rpc_config: crate::autopsy::rpc_client::RpcConfig::default(),
        },
        analysis_config,
        prefilter_only,
        prefilter_config: Some(prefilter_config),
        whitelist: if whitelist_engine.is_empty() {
            None
        } else {
            Some(whitelist_engine)
        },
        #[cfg(feature = "ai_agent")]
        ai_config: if ai_enabled {
            let mut ai_cfg = full_config.ai.clone();
            ai_cfg.enabled = true;
            Some(ai_cfg)
        } else {
            None
        },
    };

    // Clone alert_file path for the HTTP history endpoint before it's consumed
    let alert_file_for_history = alert_file.clone();

    // Build AlertDispatcher: stdout always, optional file + webhook
    let mut dispatcher = AlertDispatcher::default();
    dispatcher.add_handler(Box::new(StdoutAlertHandler));
    if let Some(path) = alert_file {
        eprintln!("[sentinel] Logging alerts to {}", path.display());
        dispatcher.add_handler(Box::new(JsonlFileAlertHandler::new(path)));
    }
    if let Some(url) = webhook_url {
        use crate::sentinel::webhook::{WebhookAlertHandler, WebhookConfig};
        eprintln!("[sentinel] Webhook notifications -> {url}");
        dispatcher.add_handler(Box::new(WebhookAlertHandler::new(WebhookConfig {
            url,
            ..WebhookConfig::default()
        })));
    }

    let (alert_tx, mut alert_rx) = mpsc::channel::<SentinelAlert>(256);

    // Start the RPC sentinel service
    let service = RpcSentinelService::start(sentinel_config, alert_tx).await;
    let metrics = service.metrics();

    // Spawn HTTP metrics server (/metrics + /health + /sentinel/*)
    {
        use crate::sentinel::http_metrics::start_metrics_server;
        let metrics_clone = metrics.clone();
        eprintln!("[sentinel] Metrics server on http://0.0.0.0:{metrics_port}/metrics");
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(
                metrics_clone,
                metrics_port,
                start_time,
                alert_file_for_history,
                None,
            )
            .await
            {
                eprintln!("[sentinel] Metrics server error: {e}");
            }
        });
    }

    // Spawn alert consumer task
    let alert_task = tokio::spawn(async move {
        while let Some(alert) = alert_rx.recv().await {
            dispatcher.on_alert(alert);
        }
    });

    // Wait for Ctrl+C or SIGTERM
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate())
            .map_err(|e| DebuggerError::Cli(format!("SIGTERM handler: {e}")))?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| DebuggerError::Cli(format!("Ctrl+C handler: {e}")))?;
    }

    eprintln!("[sentinel] Shutting down...");

    // Shutdown service and collect final metrics
    let final_metrics = metrics.snapshot();
    service.shutdown().await;
    alert_task.abort();

    // Print metrics summary
    let uptime = start_time.elapsed();
    let total_secs = uptime.as_secs();
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    let uptime_str = if days > 0 {
        format!("{days}d {hours}h {mins}m {secs}s")
    } else if hours > 0 {
        format!("{hours}h {mins}m {secs}s")
    } else {
        format!("{mins}m {secs}s")
    };

    eprintln!("[sentinel] Shutdown complete.");
    eprintln!(
        "[sentinel] blocks_scanned: {}",
        final_metrics.blocks_scanned
    );
    eprintln!("[sentinel] txs_scanned: {}", final_metrics.txs_scanned);
    eprintln!("[sentinel] txs_flagged: {}", final_metrics.txs_flagged);
    eprintln!(
        "[sentinel] alerts_emitted: {}",
        final_metrics.alerts_emitted
    );
    eprintln!("[sentinel] uptime: {uptime_str}");

    Ok(())
}

#[cfg(all(test, feature = "sentinel", feature = "autopsy"))]
mod tests;
