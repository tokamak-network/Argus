//! CLI entry point for the argus binary.

pub mod commands;
pub mod formatter;
pub mod repl;

use std::sync::Arc;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use ethrex_common::{
    Address, U256,
    constants::EMPTY_TRIE_HASH,
    types::{
        Account, BlockHeader, Code, EIP1559Transaction, LegacyTransaction, Transaction, TxKind,
    },
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
        #[arg(long)]
        tx_hash: String,

        /// Ethereum archive node RPC URL
        #[arg(long)]
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
        } => run_autopsy(
            &tx_hash,
            &rpc_url,
            block_number,
            &format,
            output.as_deref(),
            rpc_timeout,
            rpc_retries,
            quiet,
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
) -> Result<(), DebuggerError> {
    use std::time::Duration;

    use ethrex_common::H256;

    use crate::autopsy::{
        classifier::AttackClassifier,
        enrichment::{collect_sstore_slots, enrich_storage_writes},
        fund_flow::FundFlowTracer,
        remote_db::RemoteVmDatabase,
        report::AutopsyReport,
        rpc_client::{EthRpcClient, RpcConfig},
    };

    let rpc_config = RpcConfig {
        timeout: Duration::from_secs(rpc_timeout),
        max_retries: rpc_retries,
        ..RpcConfig::default()
    };

    eprintln!("[autopsy] Fetching transaction...");

    // Parse tx hash
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
    let tx_hash = H256::from_slice(&hash_bytes);

    // Use a temporary client to fetch the transaction and determine block
    let temp_client = EthRpcClient::with_config(rpc_url, 0, rpc_config.clone());
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

    eprintln!("[autopsy] Block #{block_num}, setting up remote database...");

    // Create remote database at the block BEFORE the tx
    let pre_block = block_num.saturating_sub(1);
    let remote_db = RemoteVmDatabase::from_rpc_with_config(rpc_url, pre_block, rpc_config.clone())
        .map_err(|e| {
            DebuggerError::Rpc(crate::error::RpcError::simple(format!("remote db: {e}")))
        })?;

    // Fetch block header for environment
    let client = remote_db.client();
    let block_header = client.eth_get_block_by_number(block_num).map_err(|e| {
        DebuggerError::Rpc(crate::error::RpcError::simple(format!("fetch block: {e}")))
    })?;

    // Build environment with proper gas fields
    let base_fee = block_header.base_fee_per_gas.unwrap_or(0);
    let effective_gas_price = if let Some(max_fee) = rpc_tx.max_fee_per_gas {
        // EIP-1559: min(max_fee, base_fee + max_priority_fee)
        let priority = rpc_tx.max_priority_fee_per_gas.unwrap_or(0);
        std::cmp::min(max_fee, base_fee + priority)
    } else {
        // Legacy: gas_price
        rpc_tx.gas_price.unwrap_or(0)
    };

    let env = Environment {
        origin: rpc_tx.from,
        gas_limit: rpc_tx.gas,
        block_gas_limit: block_header.gas_limit,
        block_number: block_header.number.into(),
        coinbase: block_header.coinbase,
        timestamp: block_header.timestamp.into(),
        base_fee_per_gas: U256::from(base_fee),
        gas_price: U256::from(effective_gas_price),
        tx_max_fee_per_gas: rpc_tx.max_fee_per_gas.map(U256::from),
        tx_max_priority_fee_per_gas: rpc_tx.max_priority_fee_per_gas.map(U256::from),
        tx_nonce: rpc_tx.nonce,
        ..Default::default()
    };

    // Build transaction — detect legacy vs EIP-1559 by checking max_fee_per_gas
    let tx_to = rpc_tx.to.map(TxKind::Call).unwrap_or(TxKind::Create);
    let tx_data = Bytes::from(rpc_tx.input);
    let tx = if let Some(max_fee) = rpc_tx.max_fee_per_gas {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            to: tx_to,
            data: tx_data,
            value: rpc_tx.value,
            nonce: rpc_tx.nonce,
            gas_limit: rpc_tx.gas,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: rpc_tx.max_priority_fee_per_gas.unwrap_or(0),
            ..Default::default()
        })
    } else {
        Transaction::LegacyTransaction(LegacyTransaction {
            to: tx_to,
            data: tx_data,
            value: rpc_tx.value,
            nonce: rpc_tx.nonce,
            gas: rpc_tx.gas,
            gas_price: U256::from(rpc_tx.gas_price.unwrap_or(0)),
            ..Default::default()
        })
    };

    eprintln!("[autopsy] Replaying transaction...");

    let mut db = GeneralizedDatabase::new(Arc::new(remote_db));
    let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())?;

    eprintln!("[autopsy] Recorded {} steps. Analyzing...", engine.len());

    // Enrich storage writes with old_value
    let mut trace = engine.into_trace();
    let slots = collect_sstore_slots(&trace.steps);
    let mut initial_values = rustc_hash::FxHashMap::default();

    // Fetch initial storage values for SSTORE slots from the pre-block state
    let pre_client = EthRpcClient::with_config(rpc_url, pre_block, rpc_config);
    for (addr, slot) in &slots {
        if let Ok(val) = pre_client.eth_get_storage_at(*addr, *slot) {
            initial_values.insert((*addr, *slot), val);
        }
    }
    enrich_storage_writes(&mut trace, &initial_values);

    // Classify attack patterns
    let patterns = AttackClassifier::classify(&trace.steps);

    // Trace fund flows
    let flows = FundFlowTracer::trace(&trace.steps);

    // Collect storage diffs
    let storage_diffs: Vec<_> = trace
        .steps
        .iter()
        .filter_map(|s| s.storage_writes.as_ref())
        .flatten()
        .cloned()
        .collect();

    // Build report
    let report = AutopsyReport::build(
        tx_hash,
        block_num,
        &trace.steps,
        patterns,
        flows,
        storage_diffs,
    );

    // Render output
    let (content, ext) = match output_format {
        "json" => {
            let json = report
                .to_json()
                .map_err(|e| DebuggerError::Report(format!("JSON serialization: {e}")))?;
            (json, "json")
        }
        _ => (report.to_markdown(), "md"),
    };

    // Determine output file path
    let file_path = match output_path {
        Some(p) => p.to_string(),
        None => {
            let hash_prefix = tx_hash_hex
                .strip_prefix("0x")
                .unwrap_or(tx_hash_hex)
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
