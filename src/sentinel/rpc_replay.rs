//! RPC-based transaction replay for Sentinel deep analysis.
//!
//! Replays a suspicious transaction against an Ethereum archive node using
//! `RemoteVmDatabase` for state access. Unlike `replay_tx_from_store` (which
//! requires a local full node with complete state), this module only needs an
//! archive RPC endpoint.
//!
//! # Known Limitations
//!
//! - **No intra-block state**: preceding transactions in the same block are
//!   NOT replayed before the target TX. The replay starts from the parent
//!   block's state. For `tx_index > 0`, balance/nonce/storage changes from
//!   earlier TXs in the same block are not reflected.
//!
//! - **Archive node required**: `RemoteVmDatabase` fetches historical state.
//!   Standard nodes only serve the latest state. Use an archive endpoint
//!   (Alchemy, Infura, etc.) with `eth_getProof` access.
//!
//! # Usage
//!
//! ```no_run
//! use argus::sentinel::rpc_replay::replay_tx_from_rpc;
//! use argus::sentinel::types::AnalysisConfig;
//! use argus::autopsy::rpc_client::{EthRpcClient, RpcBlock};
//!
//! let rpc_url = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY";
//! let block_number = 21_000_000_u64;
//! let client = EthRpcClient::new(rpc_url, block_number);
//! let rpc_block = client.eth_get_block_by_number_with_txs(block_number).unwrap();
//! let config = AnalysisConfig::default();
//! let result = replay_tx_from_rpc(rpc_url, block_number, 0, &rpc_block, &config);
//! ```

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use ethrex_levm::db::gen_db::GeneralizedDatabase;
use ethrex_levm::tracing::LevmCallTracer;
use ethrex_levm::vm::{VM, VMType};

use ethrex_levm::errors::TxResult;

use crate::autopsy::remote_db::RemoteVmDatabase;
use crate::autopsy::rpc_client::RpcBlock;
use crate::engine::revert_cause_from_vm_error;
use crate::recorder::DebugRecorder;
use crate::types::{ReplayConfig, ReplayTrace};

use super::replay::ReplayResult;
use super::rpc_types::{build_env_from_rpc, rpc_header_to_ethrex, rpc_tx_to_ethrex};
use super::types::{AnalysisConfig, SentinelError};

/// Replay a specific transaction from an archive RPC endpoint with opcode recording.
///
/// Steps:
/// 1. Create `RemoteVmDatabase` at `block_number - 1` (parent state before this block)
/// 2. Build `Environment` from RPC block header + target transaction
/// 3. Convert the RPC transaction to an ethrex `Transaction`
/// 4. Execute the target TX with `DebugRecorder` attached
/// 5. Return the captured `ReplayResult`
///
/// The `rpc_block` must have been fetched with `eth_getBlockByNumber(block_number, full=true)`
/// so that `rpc_block.transactions` is populated.
///
/// # Errors
///
/// - `SentinelError::TxNotFound` — `tx_index >= rpc_block.transactions.len()`
/// - `SentinelError::Db` — `RemoteVmDatabase` creation failed (bad RPC URL, network error)
/// - `SentinelError::Vm` — Transaction conversion or EVM execution failed
/// - `SentinelError::StepLimitExceeded` — recorded steps exceed `config.max_steps`
pub fn replay_tx_from_rpc(
    rpc_url: &str,
    block_number: u64,
    tx_index: usize,
    rpc_block: &RpcBlock,
    config: &AnalysisConfig,
) -> Result<ReplayResult, SentinelError> {
    // Validate tx_index
    if tx_index >= rpc_block.transactions.len() {
        return Err(SentinelError::TxNotFound {
            block_number,
            tx_index,
        });
    }

    let rpc_tx = &rpc_block.transactions[tx_index];

    // Build RemoteVmDatabase at parent block state (block_number - 1)
    let parent_block = block_number.saturating_sub(1);
    let remote_db = RemoteVmDatabase::from_rpc(rpc_url, parent_block)
        .map_err(|e| SentinelError::Db(format!("RemoteVmDatabase: {e}")))?;

    // Build LEVM Environment
    let env = build_env_from_rpc(rpc_tx, &rpc_block.header);

    // Convert RPC TX to ethrex Transaction
    let tx = rpc_tx_to_ethrex(rpc_tx)?;

    // Set up recorder
    let replay_config = ReplayConfig::default();
    let recorder = Rc::new(RefCell::new(DebugRecorder::new(replay_config.clone())));

    // Create GeneralizedDatabase wrapper (required by VM::new)
    let mut db = GeneralizedDatabase::new(Arc::new(remote_db));

    // Create VM with opcode recorder
    let mut vm = VM::new(env, &mut db, &tx, LevmCallTracer::disabled(), VMType::L1)
        .map_err(|e| SentinelError::Vm(format!("VM::new: {e}")))?;

    vm.opcode_recorder = Some(recorder.clone());

    let report = vm
        .execute()
        .map_err(|e| SentinelError::Vm(format!("VM::execute: {e}")))?;

    // Extract steps from recorder
    let steps = std::mem::take(&mut recorder.borrow_mut().steps);

    // Enforce step limit
    if steps.len() > config.max_steps {
        return Err(SentinelError::StepLimitExceeded {
            steps: steps.len(),
            max_steps: config.max_steps,
        });
    }

    let revert_cause = if let TxResult::Revert(ref err) = report.result {
        Some(revert_cause_from_vm_error(err))
    } else {
        None
    };

    let trace = ReplayTrace {
        steps,
        config: replay_config,
        gas_used: report.gas_used,
        success: report.is_success(),
        output: report.output,
        success_override: None,
        #[cfg(feature = "autopsy")]
        receipt_fund_flows: Vec::new(),
        data_quality: crate::types::DataQuality::High,
        revert_cause,
    };

    // Build block header from RPC header for ReplayResult
    let block_header = rpc_header_to_ethrex(&rpc_block.header);

    Ok(ReplayResult {
        trace,
        tx_sender: rpc_tx.from,
        block_header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopsy::rpc_client::{RpcBlock, RpcBlockHeader, RpcTransaction};
    use ethrex_common::{Address, H256, U256};

    /// Construct a minimal `RpcBlock` with `n` synthetic legacy transactions.
    fn make_rpc_block(n: usize) -> RpcBlock {
        let header = RpcBlockHeader {
            hash: H256::zero(),
            number: 21_000_000,
            timestamp: 1_700_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(10_000_000_000), // 10 gwei
            coinbase: Address::from_low_u64_be(0x01),
        };

        let transactions = (0..n)
            .map(|i| RpcTransaction {
                hash: H256::zero(),
                from: Address::from_low_u64_be(0x100 + i as u64),
                to: Some(Address::from_low_u64_be(0x42)),
                value: U256::zero(),
                input: vec![],
                gas: 21_000,
                gas_price: Some(12_000_000_000), // 12 gwei
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                nonce: i as u64,
                block_number: Some(21_000_000),
            })
            .collect();

        RpcBlock {
            header,
            transactions,
        }
    }

    /// Verify that `replay_tx_from_rpc` returns `TxNotFound` when tx_index is out of bounds.
    #[test]
    fn test_invalid_tx_index_empty_block() {
        let rpc_block = make_rpc_block(0);
        let config = AnalysisConfig::default();

        let result =
            replay_tx_from_rpc("http://localhost:8545", 21_000_000, 0, &rpc_block, &config);

        assert!(
            matches!(
                result,
                Err(SentinelError::TxNotFound {
                    block_number: 21_000_000,
                    tx_index: 0
                })
            ),
            "expected TxNotFound error"
        );
    }

    /// Verify that `replay_tx_from_rpc` returns `TxNotFound` when tx_index >= len.
    #[test]
    fn test_invalid_tx_index_out_of_bounds() {
        let rpc_block = make_rpc_block(2);
        let config = AnalysisConfig::default();

        let result =
            replay_tx_from_rpc("http://localhost:8545", 21_000_000, 5, &rpc_block, &config);

        assert!(
            matches!(
                result,
                Err(SentinelError::TxNotFound {
                    block_number: 21_000_000,
                    tx_index: 5
                })
            ),
            "expected TxNotFound for index 5 in 2-tx block"
        );
    }

    /// Verify that `replay_tx_from_rpc` fails with a Db error when given an invalid RPC URL.
    /// The error must be a Db variant (from RemoteVmDatabase::from_rpc failure).
    #[test]
    fn test_invalid_rpc_url_returns_db_error() {
        let rpc_block = make_rpc_block(1);
        let config = AnalysisConfig::default();

        // Use a URL that will definitely fail to connect
        let result = replay_tx_from_rpc(
            "http://127.0.0.1:1", // port 1 — connection refused
            21_000_000,
            0,
            &rpc_block,
            &config,
        );

        assert!(
            matches!(result, Err(SentinelError::Db(_))),
            "expected Db error for unreachable RPC"
        );
    }

    /// Verify that `StepLimitExceeded` is constructed and matched correctly,
    /// mirroring the enforcement branch in `replay_tx_from_rpc`.
    #[test]
    fn test_step_limit_error_construction() {
        let err = SentinelError::StepLimitExceeded {
            steps: 15,
            max_steps: 10,
        };
        match err {
            SentinelError::StepLimitExceeded { steps, max_steps } => {
                assert_eq!(steps, 15);
                assert_eq!(max_steps, 10);
            }
            _ => panic!("expected StepLimitExceeded"),
        }
    }

    /// Verify that ReplayResult's fields are correctly structured for downstream use.
    ///
    /// This is a structural test: builds the expected types and confirms they compose
    /// correctly with the sentinel pipeline types.
    #[test]
    fn test_replay_result_structure() {
        use crate::types::StepRecord;

        // A ReplayResult contains: trace, tx_sender, block_header
        let trace = ReplayTrace {
            steps: vec![StepRecord {
                step_index: 0,
                pc: 0,
                opcode: 0x00, // STOP
                depth: 0,
                gas_remaining: 21_000,
                stack_top: vec![],
                stack_depth: 0,
                memory_size: 0,
                code_address: Address::zero(),
                call_value: None,
                storage_writes: None,
                log_topics: None,
                log_data: None,
                call_input_selector: None,
            }],
            config: ReplayConfig::default(),
            gas_used: 21_000,
            success: true,
            output: bytes::Bytes::new(),
            success_override: None,
            #[cfg(feature = "autopsy")]
            receipt_fund_flows: Vec::new(),
            data_quality: crate::types::DataQuality::High,
            revert_cause: None,
        };

        let block_header = ethrex_common::types::BlockHeader {
            number: 21_000_000,
            timestamp: 1_700_000_000,
            ..Default::default()
        };

        let result = ReplayResult {
            trace,
            tx_sender: Address::from_low_u64_be(0x100),
            block_header,
        };

        assert_eq!(result.trace.steps.len(), 1);
        assert!(result.trace.success);
        assert_eq!(result.trace.gas_used, 21_000);
        assert_eq!(result.tx_sender, Address::from_low_u64_be(0x100));
        assert_eq!(result.block_header.number, 21_000_000);
    }

    // =========================================================================
    // Live RPC tests (require ARCHIVE_RPC_URL or ALCHEMY_API_KEY env var)
    // =========================================================================

    #[test]
    #[ignore]
    fn test_replay_bybit_tx_live() {
        // Bybit (2025-02-21) — $1.5B Safe{Wallet} supply chain attack.
        // TX: 0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882
        // Block: ~21,989,247 (approximate — verify from etherscan)
        let rpc_url = std::env::var("ARCHIVE_RPC_URL")
            .or_else(|_| {
                std::env::var("ALCHEMY_API_KEY")
                    .map(|k| format!("https://eth-mainnet.g.alchemy.com/v2/{k}"))
            })
            .expect("ARCHIVE_RPC_URL or ALCHEMY_API_KEY required");

        // Use a simple well-known TX: the DAO hack (block 1718497, tx_index 0)
        let block_number = 1_718_497_u64;
        let client = crate::autopsy::rpc_client::EthRpcClient::new(&rpc_url, block_number);
        let rpc_block = client
            .eth_get_block_by_number_with_txs(block_number)
            .expect("failed to fetch block");

        assert!(
            !rpc_block.transactions.is_empty(),
            "block should have transactions"
        );

        let config = AnalysisConfig {
            max_steps: 2_000_000, // DAO hack is complex
            ..Default::default()
        };

        let result = replay_tx_from_rpc(&rpc_url, block_number, 0, &rpc_block, &config)
            .expect("replay should succeed");

        eprintln!(
            "[rpc_replay] block={block_number} tx_index=0 steps={} success={}",
            result.trace.steps.len(),
            result.trace.success
        );

        // The DAO hack TX has many steps (recursive reentrancy)
        assert!(
            result.trace.steps.len() > 10,
            "expected many opcode steps for DAO hack"
        );
    }
}
