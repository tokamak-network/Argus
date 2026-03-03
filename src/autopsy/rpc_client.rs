//! Thin JSON-RPC HTTP client for Ethereum archive nodes.
//!
//! Supports configurable timeouts, exponential backoff retry, and
//! rate-limit awareness (HTTP 429 + Retry-After).

use std::time::Duration;

use ethrex_common::{Address, H256, U256};
use serde_json::{Value, json};

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

/// Minimal Ethereum JSON-RPC client using blocking HTTP.
pub struct EthRpcClient {
    http: reqwest::blocking::Client,
    url: String,
    block_tag: String,
    config: RpcConfig,
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

impl EthRpcClient {
    pub fn new(url: &str, block_number: u64) -> Self {
        Self::with_config(url, block_number, RpcConfig::default())
    }

    pub fn with_config(url: &str, block_number: u64, config: RpcConfig) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            http,
            url: url.to_string(),
            block_tag: format!("0x{block_number:x}"),
            config,
        }
    }

    pub fn block_number(&self) -> u64 {
        u64::from_str_radix(self.block_tag.trim_start_matches("0x"), 16).unwrap_or(0)
    }

    pub fn config(&self) -> &RpcConfig {
        &self.config
    }

    pub fn eth_get_code(&self, addr: Address) -> Result<Vec<u8>, DebuggerError> {
        let result = self.rpc_call(
            "eth_getCode",
            json!([format!("0x{addr:x}"), &self.block_tag]),
        )?;
        let hex_str = result.as_str().ok_or_else(|| RpcError::ParseError {
            method: "eth_getCode".into(),
            field: "result".into(),
            cause: "expected string".into(),
        })?;
        hex_decode(hex_str)
    }

    pub fn eth_get_balance(&self, addr: Address) -> Result<U256, DebuggerError> {
        let result = self.rpc_call(
            "eth_getBalance",
            json!([format!("0x{addr:x}"), &self.block_tag]),
        )?;
        parse_u256(&result)
    }

    pub fn eth_get_transaction_count(&self, addr: Address) -> Result<u64, DebuggerError> {
        let result = self.rpc_call(
            "eth_getTransactionCount",
            json!([format!("0x{addr:x}"), &self.block_tag]),
        )?;
        parse_u64(&result)
    }

    pub fn eth_get_storage_at(&self, addr: Address, slot: H256) -> Result<U256, DebuggerError> {
        let result = self.rpc_call(
            "eth_getStorageAt",
            json!([
                format!("0x{addr:x}"),
                format!("0x{slot:x}"),
                &self.block_tag
            ]),
        )?;
        parse_u256(&result)
    }

    pub fn eth_get_block_by_number(
        &self,
        block_number: u64,
    ) -> Result<RpcBlockHeader, DebuggerError> {
        let tag = format!("0x{block_number:x}");
        let result = self.rpc_call("eth_getBlockByNumber", json!([tag, false]))?;
        parse_block_header(&result)
    }

    pub fn eth_get_transaction_by_hash(&self, hash: H256) -> Result<RpcTransaction, DebuggerError> {
        let result = self.rpc_call("eth_getTransactionByHash", json!([format!("0x{hash:x}")]))?;
        parse_transaction(&result)
    }

    pub fn eth_chain_id(&self) -> Result<u64, DebuggerError> {
        let result = self.rpc_call("eth_chainId", json!([]))?;
        parse_u64(&result)
    }

    /// Fetch the target block header (at the client's configured block_tag).
    pub fn eth_get_target_block(&self) -> Result<RpcBlockHeader, DebuggerError> {
        self.eth_get_block_by_number(self.block_number())
    }

    /// Execute a JSON-RPC call with retry and backoff.
    fn rpc_call(&self, method: &str, params: Value) -> Result<Value, DebuggerError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        let max_attempts = self.config.max_retries + 1; // 1 initial + N retries
        let mut last_error: Option<RpcError> = None;

        for attempt in 0..max_attempts {
            if attempt > 0 {
                // Exponential backoff: base * 2^(attempt-1)
                let backoff = if let Some(ref err) = last_error {
                    // Respect Retry-After header for 429s
                    err.retry_after_secs()
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| {
                            self.config.base_backoff * 2u32.saturating_pow(attempt - 1)
                        })
                } else {
                    self.config.base_backoff * 2u32.saturating_pow(attempt - 1)
                };
                std::thread::sleep(backoff);
            }

            match self.rpc_call_once(method, &body) {
                Ok(val) => return Ok(val),
                Err(err) => {
                    if !err.is_retryable() || attempt + 1 >= max_attempts {
                        if attempt > 0 {
                            return Err(RpcError::RetryExhausted {
                                method: method.into(),
                                attempts: attempt + 1,
                                last_error: Box::new(err),
                            }
                            .into());
                        }
                        return Err(err.into());
                    }
                    last_error = Some(err);
                }
            }
        }

        // Should never reach here, but handle gracefully
        Err(last_error
            .map(|e| RpcError::RetryExhausted {
                method: method.into(),
                attempts: max_attempts,
                last_error: Box::new(e),
            })
            .unwrap_or_else(|| RpcError::simple(format!("{method}: unknown error")))
            .into())
    }

    /// Single attempt at an RPC call (no retry).
    fn rpc_call_once(&self, method: &str, body: &Value) -> Result<Value, RpcError> {
        let response = self.http.post(&self.url).json(body).send().map_err(|e| {
            if e.is_timeout() {
                RpcError::Timeout {
                    method: method.into(),
                    elapsed_ms: self.config.timeout.as_millis() as u64,
                }
            } else {
                RpcError::ConnectionFailed {
                    url: self.url.clone(),
                    cause: e.to_string(),
                }
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            // Extract Retry-After header for 429 responses
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .map(|v| format!("retry-after:{v}"))
                .unwrap_or_default();

            let body_text = response.text().unwrap_or_default();
            let display_body = if retry_after.is_empty() {
                body_text
            } else {
                retry_after
            };

            return Err(RpcError::HttpError {
                method: method.into(),
                status: status.as_u16(),
                body: display_body,
            });
        }

        let json_response: Value = response.json().map_err(|e| RpcError::ParseError {
            method: method.into(),
            field: "response_body".into(),
            cause: e.to_string(),
        })?;

        if let Some(error) = json_response.get("error") {
            let code = error.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
                .to_string();
            return Err(RpcError::JsonRpcError {
                method: method.into(),
                code,
                message,
            });
        }

        json_response
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::ParseError {
                method: method.into(),
                field: "result".into(),
                cause: "missing result field".into(),
            })
    }
}

// --- Parsing helpers ---

fn hex_decode(hex_str: &str) -> Result<Vec<u8>, DebuggerError> {
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

fn parse_u64(val: &Value) -> Result<u64, DebuggerError> {
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

fn parse_u256(val: &Value) -> Result<U256, DebuggerError> {
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

fn parse_h256(val: &Value) -> Result<H256, DebuggerError> {
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

fn parse_address(val: &Value) -> Result<Address, DebuggerError> {
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

fn parse_block_header(val: &Value) -> Result<RpcBlockHeader, DebuggerError> {
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

fn parse_transaction(val: &Value) -> Result<RpcTransaction, DebuggerError> {
    if val.is_null() {
        return Err(RpcError::ParseError {
            method: "eth_getTransactionByHash".into(),
            field: "result".into(),
            cause: "transaction not found".into(),
        }
        .into());
    }
    Ok(RpcTransaction {
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

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- Phase I tests ---

    #[test]
    fn test_rpc_config_defaults() {
        let config = RpcConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.base_backoff, Duration::from_secs(1));
    }

    #[test]
    fn test_rpc_error_retryable_connection() {
        let err = RpcError::ConnectionFailed {
            url: "http://localhost".into(),
            cause: "refused".into(),
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_rpc_error_retryable_timeout() {
        let err = RpcError::Timeout {
            method: "eth_call".into(),
            elapsed_ms: 30000,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn test_rpc_error_retryable_rate_limit() {
        let err = RpcError::HttpError {
            method: "eth_call".into(),
            status: 429,
            body: "retry-after:2".into(),
        };
        assert!(err.is_retryable());
        assert_eq!(err.retry_after_secs(), Some(2));
    }

    #[test]
    fn test_rpc_error_retryable_server_errors() {
        for status in [502, 503, 504] {
            let err = RpcError::HttpError {
                method: "eth_call".into(),
                status,
                body: String::new(),
            };
            assert!(err.is_retryable(), "HTTP {status} should be retryable");
        }
    }

    #[test]
    fn test_rpc_error_not_retryable_client_errors() {
        for status in [400, 401, 404] {
            let err = RpcError::HttpError {
                method: "eth_call".into(),
                status,
                body: String::new(),
            };
            assert!(!err.is_retryable(), "HTTP {status} should NOT be retryable");
        }
    }

    #[test]
    fn test_rpc_error_not_retryable_json_rpc() {
        let err = RpcError::JsonRpcError {
            method: "eth_call".into(),
            code: -32601,
            message: "method not found".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_rpc_error_not_retryable_parse() {
        let err = RpcError::ParseError {
            method: "eth_call".into(),
            field: "result".into(),
            cause: "invalid hex".into(),
        };
        assert!(!err.is_retryable());
    }

    #[test]
    fn test_rpc_error_display_formatting() {
        let err = RpcError::Timeout {
            method: "eth_getBalance".into(),
            elapsed_ms: 30000,
        };
        let msg = format!("{err}");
        assert!(msg.contains("eth_getBalance"));
        assert!(msg.contains("30000"));
    }

    #[test]
    fn test_rpc_error_retry_exhausted_display() {
        let inner = RpcError::Timeout {
            method: "eth_call".into(),
            elapsed_ms: 30000,
        };
        let err = RpcError::RetryExhausted {
            method: "eth_call".into(),
            attempts: 4,
            last_error: Box::new(inner),
        };
        let msg = format!("{err}");
        assert!(msg.contains("4 attempt(s)"));
        assert!(msg.contains("eth_call"));
    }

    #[test]
    fn test_rpc_error_json_rpc_code_extraction() {
        let err = RpcError::JsonRpcError {
            method: "eth_call".into(),
            code: -32000,
            message: "execution reverted".into(),
        };
        if let RpcError::JsonRpcError { code, message, .. } = &err {
            assert_eq!(*code, -32000);
            assert_eq!(message, "execution reverted");
        }
    }

    #[test]
    fn test_client_with_custom_config() {
        let config = RpcConfig {
            timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(2),
            max_retries: 1,
            base_backoff: Duration::from_millis(100),
        };
        let client = EthRpcClient::with_config("http://localhost:8545", 100, config);
        assert_eq!(client.config().timeout, Duration::from_secs(5));
        assert_eq!(client.config().max_retries, 1);
        assert_eq!(client.block_number(), 100);
    }
}
