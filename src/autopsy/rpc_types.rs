//! RPC response types, JSON parsing helpers, and ethrex type conversions.
//!
//! Defines the data types returned by Ethereum JSON-RPC methods, the
//! parsing functions that convert raw `serde_json::Value` into typed structs,
//! and conversion functions to ethrex-native types (`Transaction`, `Environment`).

use std::time::Duration;

use bytes::Bytes;
use ethrex_common::types::{EIP1559Transaction, LegacyTransaction, Transaction, TxKind};
use ethrex_common::{Address, H256, U256};
use ethrex_levm::Environment;
use serde_json::Value;

use crate::error::{DebuggerError, RpcError};

/// Configuration for RPC client behavior.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Per-request timeout (default: 30s).
    pub timeout: Duration,
    /// TCP connect timeout (default: 10s).
    pub connect_timeout: Duration,
    /// Maximum retry attempts for transient errors (default: 3).
    pub max_retries: u32,
    /// Base backoff duration — doubles each retry (default: 1s).
    pub base_backoff: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            max_retries: 3,
            base_backoff: Duration::from_secs(1),
        }
    }
}

/// Subset of block header fields returned by `eth_getBlockByNumber`.
#[derive(Debug, Clone)]
pub struct RpcBlockHeader {
    pub hash: H256,
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub base_fee_per_gas: Option<u64>,
    pub coinbase: Address,
}

/// Subset of transaction fields returned by `eth_getTransactionByHash`.
#[derive(Debug, Clone)]
pub struct RpcTransaction {
    /// Transaction hash (may be zero-hash for legacy transactions without hash field).
    pub hash: H256,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub input: Vec<u8>,
    pub gas: u64,
    pub gas_price: Option<u64>,
    pub max_fee_per_gas: Option<u64>,
    pub max_priority_fee_per_gas: Option<u64>,
    pub nonce: u64,
    pub block_number: Option<u64>,
}

/// Full block with transactions returned by `eth_getBlockByNumber` with `full=true`.
#[derive(Debug, Clone)]
pub struct RpcBlock {
    pub header: RpcBlockHeader,
    pub transactions: Vec<RpcTransaction>,
}

/// Transaction receipt returned by `eth_getTransactionReceipt`.
#[derive(Debug, Clone)]
pub struct RpcReceipt {
    pub status: bool,
    pub cumulative_gas_used: u64,
    pub logs: Vec<RpcLog>,
    pub transaction_hash: H256,
    pub transaction_index: u64,
    pub gas_used: u64,
}

/// Log entry from a transaction receipt.
#[derive(Debug, Clone)]
pub struct RpcLog {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

// --- Parsing helpers ---

pub(crate) fn hex_decode(hex_str: &str) -> Result<Vec<u8>, DebuggerError> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| {
                RpcError::ParseError {
                    method: String::new(),
                    field: "hex".into(),
                    cause: e.to_string(),
                }
                .into()
            })
        })
        .collect()
}

pub(crate) fn parse_u64(val: &Value) -> Result<u64, DebuggerError> {
    let s = val.as_str().ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: String::new(),
            field: "u64".into(),
            cause: "expected hex string".into(),
        })
    })?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| {
        RpcError::ParseError {
            method: String::new(),
            field: "u64".into(),
            cause: e.to_string(),
        }
        .into()
    })
}

pub(crate) fn parse_u256(val: &Value) -> Result<U256, DebuggerError> {
    let s = val.as_str().ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: String::new(),
            field: "U256".into(),
            cause: "expected hex string".into(),
        })
    })?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    U256::from_str_radix(s, 16).map_err(|e| {
        RpcError::ParseError {
            method: String::new(),
            field: "U256".into(),
            cause: e.to_string(),
        }
        .into()
    })
}

pub(crate) fn parse_h256(val: &Value) -> Result<H256, DebuggerError> {
    let s = val.as_str().ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: String::new(),
            field: "H256".into(),
            cause: "expected hex string".into(),
        })
    })?;
    let bytes = hex_decode(s)?;
    if bytes.len() != 32 {
        return Err(RpcError::ParseError {
            method: String::new(),
            field: "H256".into(),
            cause: format!("expected 32 bytes, got {}", bytes.len()),
        }
        .into());
    }
    Ok(H256::from_slice(&bytes))
}

pub(crate) fn parse_address(val: &Value) -> Result<Address, DebuggerError> {
    let s = val.as_str().ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: String::new(),
            field: "Address".into(),
            cause: "expected hex string".into(),
        })
    })?;
    let bytes = hex_decode(s)?;
    if bytes.len() != 20 {
        return Err(RpcError::ParseError {
            method: String::new(),
            field: "Address".into(),
            cause: format!("expected 20 bytes, got {}", bytes.len()),
        }
        .into());
    }
    Ok(Address::from_slice(&bytes))
}

pub(crate) fn parse_block_header(val: &Value) -> Result<RpcBlockHeader, DebuggerError> {
    if val.is_null() {
        return Err(RpcError::ParseError {
            method: "eth_getBlockByNumber".into(),
            field: "result".into(),
            cause: "block not found".into(),
        }
        .into());
    }
    Ok(RpcBlockHeader {
        hash: parse_h256(val.get("hash").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getBlockByNumber".into(),
                field: "hash".into(),
                cause: "missing".into(),
            })
        })?)?,
        number: parse_u64(val.get("number").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getBlockByNumber".into(),
                field: "number".into(),
                cause: "missing".into(),
            })
        })?)?,
        timestamp: parse_u64(val.get("timestamp").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getBlockByNumber".into(),
                field: "timestamp".into(),
                cause: "missing".into(),
            })
        })?)?,
        gas_limit: parse_u64(val.get("gasLimit").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getBlockByNumber".into(),
                field: "gasLimit".into(),
                cause: "missing".into(),
            })
        })?)?,
        base_fee_per_gas: val.get("baseFeePerGas").and_then(|v| parse_u64(v).ok()),
        coinbase: parse_address(val.get("miner").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getBlockByNumber".into(),
                field: "miner".into(),
                cause: "missing".into(),
            })
        })?)?,
    })
}

pub(crate) fn parse_transaction(val: &Value) -> Result<RpcTransaction, DebuggerError> {
    if val.is_null() {
        return Err(RpcError::ParseError {
            method: "eth_getTransactionByHash".into(),
            field: "result".into(),
            cause: "transaction not found".into(),
        }
        .into());
    }
    Ok(RpcTransaction {
        hash: val
            .get("hash")
            .and_then(|v| parse_h256(v).ok())
            .unwrap_or_else(H256::zero),
        from: parse_address(val.get("from").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getTransactionByHash".into(),
                field: "from".into(),
                cause: "missing".into(),
            })
        })?)?,
        to: val
            .get("to")
            .and_then(|v| if v.is_null() { None } else { Some(v) })
            .and_then(|v| parse_address(v).ok()),
        value: parse_u256(val.get("value").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getTransactionByHash".into(),
                field: "value".into(),
                cause: "missing".into(),
            })
        })?)?,
        input: {
            let input_val = val.get("input").ok_or_else(|| {
                DebuggerError::from(RpcError::ParseError {
                    method: "eth_getTransactionByHash".into(),
                    field: "input".into(),
                    cause: "missing".into(),
                })
            })?;
            hex_decode(input_val.as_str().unwrap_or("0x"))?
        },
        gas: parse_u64(val.get("gas").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getTransactionByHash".into(),
                field: "gas".into(),
                cause: "missing".into(),
            })
        })?)?,
        gas_price: val.get("gasPrice").and_then(|v| parse_u64(v).ok()),
        max_fee_per_gas: val.get("maxFeePerGas").and_then(|v| parse_u64(v).ok()),
        max_priority_fee_per_gas: val
            .get("maxPriorityFeePerGas")
            .and_then(|v| parse_u64(v).ok()),
        nonce: parse_u64(val.get("nonce").ok_or_else(|| {
            DebuggerError::from(RpcError::ParseError {
                method: "eth_getTransactionByHash".into(),
                field: "nonce".into(),
                cause: "missing".into(),
            })
        })?)?,
        block_number: val.get("blockNumber").and_then(|v| parse_u64(v).ok()),
    })
}

pub(crate) fn parse_rpc_block(val: &Value) -> Result<RpcBlock, DebuggerError> {
    if val.is_null() {
        return Err(RpcError::ParseError {
            method: "eth_getBlockByNumber".into(),
            field: "result".into(),
            cause: "block not found".into(),
        }
        .into());
    }
    let header = parse_block_header(val)?;
    let transactions = val
        .get("transactions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(parse_transaction)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(RpcBlock {
        header,
        transactions,
    })
}

pub(crate) fn parse_rpc_receipt(val: &Value) -> Result<RpcReceipt, DebuggerError> {
    if val.is_null() {
        return Err(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "result".into(),
            cause: "receipt not found".into(),
        }
        .into());
    }
    let status_val = val.get("status").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "status".into(),
            cause: "missing".into(),
        })
    })?;
    let status = parse_u64(status_val)? != 0;

    let cumulative_gas_used = parse_u64(val.get("cumulativeGasUsed").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "cumulativeGasUsed".into(),
            cause: "missing".into(),
        })
    })?)?;

    let gas_used = parse_u64(val.get("gasUsed").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "gasUsed".into(),
            cause: "missing".into(),
        })
    })?)?;

    let transaction_hash = parse_h256(val.get("transactionHash").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "transactionHash".into(),
            cause: "missing".into(),
        })
    })?)?;

    let transaction_index = parse_u64(val.get("transactionIndex").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "transactionIndex".into(),
            cause: "missing".into(),
        })
    })?)?;

    let logs = val
        .get("logs")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(parse_rpc_log).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    Ok(RpcReceipt {
        status,
        cumulative_gas_used,
        logs,
        transaction_hash,
        transaction_index,
        gas_used,
    })
}

pub(crate) fn parse_rpc_log(val: &Value) -> Result<RpcLog, DebuggerError> {
    let address = parse_address(val.get("address").ok_or_else(|| {
        DebuggerError::from(RpcError::ParseError {
            method: "eth_getTransactionReceipt".into(),
            field: "log.address".into(),
            cause: "missing".into(),
        })
    })?)?;

    let topics = val
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(parse_h256).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();

    let data = val
        .get("data")
        .and_then(|v| v.as_str())
        .map(hex_decode)
        .transpose()?
        .unwrap_or_default();

    Ok(RpcLog {
        address,
        topics,
        data,
    })
}

// ---------------------------------------------------------------------------
// ethrex type conversions (shared by autopsy CLI and sentinel pipeline)
// ---------------------------------------------------------------------------

/// Convert an `RpcTransaction` into ethrex `Transaction` (Legacy or EIP-1559).
pub fn rpc_tx_to_ethrex(rpc: &RpcTransaction) -> Transaction {
    let to = rpc.to.map(TxKind::Call).unwrap_or(TxKind::Create);
    let data = Bytes::from(rpc.input.clone());

    if let Some(max_fee) = rpc.max_fee_per_gas {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            to,
            data,
            value: rpc.value,
            nonce: rpc.nonce,
            gas_limit: rpc.gas,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: rpc.max_priority_fee_per_gas.unwrap_or(0),
            ..Default::default()
        })
    } else {
        Transaction::LegacyTransaction(LegacyTransaction {
            to,
            data,
            value: rpc.value,
            nonce: rpc.nonce,
            gas: rpc.gas,
            gas_price: U256::from(rpc.gas_price.unwrap_or(0)),
            ..Default::default()
        })
    }
}

/// Build an EVM `Environment` from an `RpcTransaction` and block header.
///
/// Computes `effective_gas_price` using EIP-1559 priority fee capping when applicable.
pub fn build_env_from_rpc(rpc_tx: &RpcTransaction, block_header: &RpcBlockHeader) -> Environment {
    let base_fee = block_header.base_fee_per_gas.unwrap_or(0);
    let effective_gas_price = if let Some(max_fee) = rpc_tx.max_fee_per_gas {
        let priority = rpc_tx.max_priority_fee_per_gas.unwrap_or(0);
        std::cmp::min(max_fee, base_fee + priority)
    } else {
        rpc_tx.gas_price.unwrap_or(0)
    };

    Environment {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hex_decode_empty() {
        assert_eq!(hex_decode("0x").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hex_decode_bytes() {
        assert_eq!(
            hex_decode("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_parse_u64_hex() {
        let val = json!("0x1a");
        assert_eq!(parse_u64(&val).unwrap(), 26);
    }

    #[test]
    fn test_parse_u256_hex() {
        let val = json!("0xff");
        assert_eq!(parse_u256(&val).unwrap(), U256::from(255));
    }

    #[test]
    fn test_parse_h256() {
        let hex = "0x000000000000000000000000000000000000000000000000000000000000002a";
        let val = json!(hex);
        let h = parse_h256(&val).unwrap();
        assert_eq!(h[31], 0x2a);
    }

    #[test]
    fn test_parse_address() {
        let val = json!("0x0000000000000000000000000000000000000042");
        let addr = parse_address(&val).unwrap();
        assert_eq!(addr, Address::from_low_u64_be(0x42));
    }

    #[test]
    fn test_parse_block_header() {
        let block = json!({
            "hash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "number": "0xa",
            "timestamp": "0x5f5e100",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x3b9aca00",
            "miner": "0x0000000000000000000000000000000000000001"
        });
        let header = parse_block_header(&block).unwrap();
        assert_eq!(header.number, 10);
        assert_eq!(header.timestamp, 100_000_000);
        assert_eq!(header.gas_limit, 30_000_000);
        assert_eq!(header.base_fee_per_gas, Some(1_000_000_000));
    }

    #[test]
    fn test_parse_transaction() {
        let tx = json!({
            "from": "0x0000000000000000000000000000000000000100",
            "to": "0x0000000000000000000000000000000000000042",
            "value": "0x0",
            "input": "0xdeadbeef",
            "gas": "0x5208",
            "gasPrice": "0x3b9aca00",
            "nonce": "0x5",
            "blockNumber": "0xa"
        });
        let parsed = parse_transaction(&tx).unwrap();
        assert_eq!(parsed.from, Address::from_low_u64_be(0x100));
        assert_eq!(parsed.to, Some(Address::from_low_u64_be(0x42)));
        assert_eq!(parsed.gas, 21000);
        assert_eq!(parsed.nonce, 5);
        assert_eq!(parsed.input, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_transaction_null_to() {
        let tx = json!({
            "from": "0x0000000000000000000000000000000000000100",
            "to": null,
            "value": "0x0",
            "input": "0x",
            "gas": "0x5208",
            "nonce": "0x0"
        });
        let parsed = parse_transaction(&tx).unwrap();
        assert!(parsed.to.is_none());
    }

    #[test]
    fn test_block_not_found() {
        let result = parse_block_header(&json!(null));
        assert!(result.is_err());
    }

    #[test]
    fn test_tx_not_found() {
        let result = parse_transaction(&json!(null));
        assert!(result.is_err());
    }

    #[test]
    fn test_rpc_config_defaults() {
        let config = RpcConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.base_backoff, Duration::from_secs(1));
    }

    #[test]
    fn test_parse_rpc_block() {
        let block = json!({
            "hash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "number": "0xa",
            "timestamp": "0x5f5e100",
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": "0x3b9aca00",
            "miner": "0x0000000000000000000000000000000000000001",
            "transactions": [
                {
                    "from": "0x0000000000000000000000000000000000000100",
                    "to": "0x0000000000000000000000000000000000000042",
                    "value": "0x0",
                    "input": "0xdeadbeef",
                    "gas": "0x5208",
                    "gasPrice": "0x3b9aca00",
                    "nonce": "0x5",
                    "blockNumber": "0xa"
                }
            ]
        });
        let rpc_block = parse_rpc_block(&block).unwrap();
        assert_eq!(rpc_block.header.number, 10);
        assert_eq!(rpc_block.transactions.len(), 1);
        assert_eq!(rpc_block.transactions[0].nonce, 5);
        assert_eq!(rpc_block.transactions[0].gas, 21000);
    }

    #[test]
    fn test_parse_rpc_block_empty_txs() {
        let block = json!({
            "hash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "number": "0x1",
            "timestamp": "0x1",
            "gasLimit": "0x1c9c380",
            "miner": "0x0000000000000000000000000000000000000001",
            "transactions": []
        });
        let rpc_block = parse_rpc_block(&block).unwrap();
        assert_eq!(rpc_block.transactions.len(), 0);
    }

    #[test]
    fn test_parse_rpc_block_null() {
        let result = parse_rpc_block(&json!(null));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpc_receipt() {
        let receipt = json!({
            "status": "0x1",
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "transactionHash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "transactionIndex": "0x0",
            "logs": []
        });
        let parsed = parse_rpc_receipt(&receipt).unwrap();
        assert!(parsed.status);
        assert_eq!(parsed.cumulative_gas_used, 21000);
        assert_eq!(parsed.gas_used, 21000);
        assert_eq!(parsed.transaction_index, 0);
        assert!(parsed.logs.is_empty());
    }

    #[test]
    fn test_parse_rpc_receipt_failed_tx() {
        let receipt = json!({
            "status": "0x0",
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "transactionHash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "transactionIndex": "0x1",
            "logs": []
        });
        let parsed = parse_rpc_receipt(&receipt).unwrap();
        assert!(!parsed.status);
    }

    #[test]
    fn test_parse_rpc_receipt_null() {
        let result = parse_rpc_receipt(&json!(null));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_rpc_log() {
        let log = json!({
            "address": "0x0000000000000000000000000000000000000042",
            "topics": [
                "0x000000000000000000000000000000000000000000000000000000000000002a",
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            ],
            "data": "0xdeadbeef"
        });
        let parsed = parse_rpc_log(&log).unwrap();
        assert_eq!(parsed.address, Address::from_low_u64_be(0x42));
        assert_eq!(parsed.topics.len(), 2);
        assert_eq!(parsed.topics[0][31], 0x2a);
        assert_eq!(parsed.data, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_rpc_log_empty_topics_and_data() {
        let log = json!({
            "address": "0x0000000000000000000000000000000000000001",
            "topics": [],
            "data": "0x"
        });
        let parsed = parse_rpc_log(&log).unwrap();
        assert!(parsed.topics.is_empty());
        assert!(parsed.data.is_empty());
    }

    #[test]
    fn test_parse_rpc_receipt_with_logs() {
        let receipt = json!({
            "status": "0x1",
            "cumulativeGasUsed": "0x10000",
            "gasUsed": "0x8000",
            "transactionHash": "0x000000000000000000000000000000000000000000000000000000000000abcd",
            "transactionIndex": "0x2",
            "logs": [
                {
                    "address": "0x0000000000000000000000000000000000000042",
                    "topics": [
                        "0x000000000000000000000000000000000000000000000000000000000000002a"
                    ],
                    "data": "0x1234"
                }
            ]
        });
        let parsed = parse_rpc_receipt(&receipt).unwrap();
        assert_eq!(parsed.logs.len(), 1);
        assert_eq!(parsed.logs[0].address, Address::from_low_u64_be(0x42));
        assert_eq!(parsed.transaction_index, 2);
    }
}
