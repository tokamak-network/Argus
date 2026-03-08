//! RPC → ethrex type conversion for Sentinel RPC mode.
//!
//! Converts `RpcBlock`, `RpcReceipt`, and `RpcTransaction` (from the autopsy
//! RPC client) into ethrex-native types used by the Sentinel pipeline.

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use bytes::Bytes;
use ethrex_common::types::{Block, BlockBody, BlockHeader, Log, Receipt, Transaction, TxType};
use ethrex_levm::Environment;

use crate::autopsy::rpc_client::{RpcBlock, RpcBlockHeader, RpcLog, RpcReceipt, RpcTransaction};
use crate::sentinel::types::SentinelError;

/// Convert an `RpcBlock` (header + full transactions) into ethrex `Block`.
pub fn rpc_block_to_ethrex(rpc_block: &RpcBlock) -> Result<Block, SentinelError> {
    let header = rpc_header_to_ethrex(&rpc_block.header);
    let transactions: Vec<Transaction> = rpc_block
        .transactions
        .iter()
        .map(crate::autopsy::rpc_types::rpc_tx_to_ethrex)
        .collect();
    Ok(Block {
        header,
        body: BlockBody {
            transactions,
            ..Default::default()
        },
    })
}

/// Convert an `RpcBlockHeader` into ethrex `BlockHeader`.
pub fn rpc_header_to_ethrex(rpc: &RpcBlockHeader) -> BlockHeader {
    BlockHeader {
        number: rpc.number,
        timestamp: rpc.timestamp,
        gas_limit: rpc.gas_limit,
        coinbase: rpc.coinbase,
        base_fee_per_gas: rpc.base_fee_per_gas,
        ..Default::default()
    }
}

/// Convert an `RpcTransaction` into ethrex `Transaction` (Legacy or EIP-1559).
///
/// Delegates to [`crate::autopsy::rpc_types::rpc_tx_to_ethrex`].
/// Kept as `Result` for backward compatibility with callers expecting `Result`.
pub fn rpc_tx_to_ethrex(rpc: &RpcTransaction) -> Result<Transaction, SentinelError> {
    Ok(crate::autopsy::rpc_types::rpc_tx_to_ethrex(rpc))
}

/// Convert an `RpcReceipt` into ethrex `Receipt`.
///
/// Always uses `TxType::Legacy`. Prefer [`rpc_receipt_to_ethrex_typed`] when
/// the corresponding `RpcTransaction` is available, so the TX type is inferred
/// correctly for EIP-1559 transactions.
pub fn rpc_receipt_to_ethrex(rpc: &RpcReceipt) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded: rpc.status,
        cumulative_gas_used: rpc.cumulative_gas_used,
        logs: rpc.logs.iter().map(rpc_log_to_ethrex).collect(),
    }
}

/// Convert an `RpcReceipt` into ethrex `Receipt` with TX type inferred from the
/// corresponding `RpcTransaction`.
///
/// Uses `TxType::EIP1559` when `rpc_tx.max_fee_per_gas` is present, and
/// `TxType::Legacy` otherwise. Call this instead of [`rpc_receipt_to_ethrex`]
/// when you have both the receipt and the matching transaction.
pub fn rpc_receipt_to_ethrex_typed(rpc: &RpcReceipt, rpc_tx: &RpcTransaction) -> Receipt {
    let tx_type = if rpc_tx.max_fee_per_gas.is_some() {
        TxType::EIP1559
    } else {
        TxType::Legacy
    };
    Receipt {
        tx_type,
        succeeded: rpc.status,
        cumulative_gas_used: rpc.cumulative_gas_used,
        logs: rpc.logs.iter().map(rpc_log_to_ethrex).collect(),
    }
}

/// Convert an `RpcLog` into ethrex `Log`.
pub fn rpc_log_to_ethrex(rpc: &RpcLog) -> Log {
    Log {
        address: rpc.address,
        topics: rpc.topics.clone(),
        data: Bytes::from(rpc.data.clone()),
    }
}

/// Build an `Environment` from an `RpcTransaction` and the block header it lives in.
///
/// Delegates to [`crate::autopsy::rpc_types::build_env_from_rpc`].
pub fn build_env_from_rpc(rpc_tx: &RpcTransaction, block_header: &RpcBlockHeader) -> Environment {
    crate::autopsy::rpc_types::build_env_from_rpc(rpc_tx, block_header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopsy::rpc_client::{
        RpcBlock, RpcBlockHeader, RpcLog, RpcReceipt, RpcTransaction,
    };
    use ethrex_common::types::TxKind;
    use ethrex_common::{Address, H256, U256};

    fn make_block_header() -> RpcBlockHeader {
        RpcBlockHeader {
            hash: H256::zero(),
            number: 10,
            timestamp: 100_000_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1_000_000_000),
            coinbase: Address::from_low_u64_be(0x01),
        }
    }

    fn make_legacy_tx() -> RpcTransaction {
        RpcTransaction {
            hash: H256::zero(),
            from: Address::from_low_u64_be(0x100),
            to: Some(Address::from_low_u64_be(0x42)),
            value: U256::zero(),
            input: vec![0xde, 0xad, 0xbe, 0xef],
            gas: 21_000,
            gas_price: Some(2_000_000_000),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: 5,
            block_number: Some(10),
        }
    }

    fn make_eip1559_tx() -> RpcTransaction {
        RpcTransaction {
            hash: H256::zero(),
            from: Address::from_low_u64_be(0x100),
            to: Some(Address::from_low_u64_be(0x42)),
            value: U256::from(1_000_000_000_000_000_000_u64),
            input: vec![],
            gas: 100_000,
            gas_price: None,
            max_fee_per_gas: Some(3_000_000_000),
            max_priority_fee_per_gas: Some(100_000_000),
            nonce: 7,
            block_number: Some(10),
        }
    }

    #[test]
    fn test_legacy_tx_conversion() {
        let rpc_tx = make_legacy_tx();
        let tx = rpc_tx_to_ethrex(&rpc_tx).unwrap();
        match tx {
            Transaction::LegacyTransaction(legacy) => {
                assert_eq!(legacy.nonce, 5);
                assert_eq!(legacy.gas, 21_000);
                assert_eq!(legacy.gas_price, U256::from(2_000_000_000_u64));
                assert_eq!(legacy.value, U256::zero());
                assert_eq!(legacy.data.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
                match legacy.to {
                    TxKind::Call(addr) => assert_eq!(addr, Address::from_low_u64_be(0x42)),
                    TxKind::Create => panic!("expected Call"),
                }
            }
            _ => panic!("expected LegacyTransaction"),
        }
    }

    #[test]
    fn test_eip1559_tx_conversion() {
        let rpc_tx = make_eip1559_tx();
        let tx = rpc_tx_to_ethrex(&rpc_tx).unwrap();
        match tx {
            Transaction::EIP1559Transaction(eip) => {
                assert_eq!(eip.nonce, 7);
                assert_eq!(eip.gas_limit, 100_000);
                assert_eq!(eip.max_fee_per_gas, 3_000_000_000);
                assert_eq!(eip.max_priority_fee_per_gas, 100_000_000);
                assert_eq!(eip.value, U256::from(1_000_000_000_000_000_000_u64));
            }
            _ => panic!("expected EIP1559Transaction"),
        }
    }

    #[test]
    fn test_legacy_tx_create() {
        let mut rpc_tx = make_legacy_tx();
        rpc_tx.to = None;
        let tx = rpc_tx_to_ethrex(&rpc_tx).unwrap();
        match tx {
            Transaction::LegacyTransaction(legacy) => {
                assert!(matches!(legacy.to, TxKind::Create));
            }
            _ => panic!("expected LegacyTransaction"),
        }
    }

    #[test]
    fn test_build_env_basic() {
        let rpc_tx = make_legacy_tx();
        let header = make_block_header();
        let env = build_env_from_rpc(&rpc_tx, &header);
        assert_eq!(env.origin, Address::from_low_u64_be(0x100));
        assert_eq!(env.gas_limit, 21_000);
        assert_eq!(env.block_gas_limit, 30_000_000);
        assert_eq!(env.block_number, 10_u64.into());
        assert_eq!(env.coinbase, Address::from_low_u64_be(0x01));
        assert_eq!(env.timestamp, 100_000_000_u64.into());
        assert_eq!(env.base_fee_per_gas, U256::from(1_000_000_000_u64));
        // Legacy: effective_gas_price = gas_price
        assert_eq!(env.gas_price, U256::from(2_000_000_000_u64));
        assert_eq!(env.tx_nonce, 5);
    }

    #[test]
    fn test_build_env_eip1559_price_cap() {
        let rpc_tx = make_eip1559_tx();
        let header = make_block_header(); // base_fee = 1 gwei
        let env = build_env_from_rpc(&rpc_tx, &header);
        // effective = min(max_fee=3gwei, base_fee=1gwei + priority=0.1gwei) = 1.1gwei
        let expected_price = 1_000_000_000_u64 + 100_000_000_u64; // 1.1 gwei
        assert_eq!(env.gas_price, U256::from(expected_price));
        assert_eq!(env.tx_max_fee_per_gas, Some(U256::from(3_000_000_000_u64)));
        assert_eq!(
            env.tx_max_priority_fee_per_gas,
            Some(U256::from(100_000_000_u64))
        );
    }

    #[test]
    fn test_receipt_typed_eip1559() {
        let rpc_receipt = RpcReceipt {
            status: true,
            cumulative_gas_used: 80_000,
            logs: vec![],
            transaction_hash: H256::zero(),
            transaction_index: 0,
            gas_used: 80_000,
        };
        let rpc_tx = make_eip1559_tx();
        let receipt = rpc_receipt_to_ethrex_typed(&rpc_receipt, &rpc_tx);
        assert_eq!(receipt.tx_type, TxType::EIP1559);
        assert!(receipt.succeeded);
        assert_eq!(receipt.cumulative_gas_used, 80_000);
    }

    #[test]
    fn test_receipt_typed_legacy() {
        let rpc_receipt = RpcReceipt {
            status: false,
            cumulative_gas_used: 21_000,
            logs: vec![],
            transaction_hash: H256::zero(),
            transaction_index: 0,
            gas_used: 21_000,
        };
        let rpc_tx = make_legacy_tx();
        let receipt = rpc_receipt_to_ethrex_typed(&rpc_receipt, &rpc_tx);
        assert_eq!(receipt.tx_type, TxType::Legacy);
        assert!(!receipt.succeeded);
    }

    #[test]
    fn test_receipt_typed_preserves_logs() {
        let log = RpcLog {
            address: Address::from_low_u64_be(0x99),
            topics: vec![H256::from([0xab; 32])],
            data: vec![0xff],
        };
        let rpc_receipt = RpcReceipt {
            status: true,
            cumulative_gas_used: 50_000,
            logs: vec![log],
            transaction_hash: H256::zero(),
            transaction_index: 0,
            gas_used: 50_000,
        };
        let rpc_tx = make_eip1559_tx();
        let receipt = rpc_receipt_to_ethrex_typed(&rpc_receipt, &rpc_tx);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].address, Address::from_low_u64_be(0x99));
        assert_eq!(receipt.logs[0].data.as_ref(), &[0xff]);
    }

    #[test]
    fn test_receipt_conversion() {
        let log = RpcLog {
            address: Address::from_low_u64_be(0x42),
            topics: vec![H256::from([0x01; 32])],
            data: vec![0xab, 0xcd],
        };
        let rpc_receipt = RpcReceipt {
            status: true,
            cumulative_gas_used: 50_000,
            logs: vec![log],
            transaction_hash: H256::zero(),
            transaction_index: 0,
            gas_used: 50_000,
        };
        let receipt = rpc_receipt_to_ethrex(&rpc_receipt);
        assert!(receipt.succeeded);
        assert_eq!(receipt.cumulative_gas_used, 50_000);
        assert_eq!(receipt.logs.len(), 1);
        assert_eq!(receipt.logs[0].address, Address::from_low_u64_be(0x42));
        assert_eq!(receipt.logs[0].topics.len(), 1);
        assert_eq!(receipt.logs[0].data.as_ref(), &[0xab, 0xcd]);
    }

    #[test]
    fn test_receipt_failed_tx() {
        let rpc_receipt = RpcReceipt {
            status: false,
            cumulative_gas_used: 21_000,
            logs: vec![],
            transaction_hash: H256::zero(),
            transaction_index: 0,
            gas_used: 21_000,
        };
        let receipt = rpc_receipt_to_ethrex(&rpc_receipt);
        assert!(!receipt.succeeded);
        assert!(receipt.logs.is_empty());
    }

    #[test]
    fn test_block_conversion() {
        let rpc_block = RpcBlock {
            header: make_block_header(),
            transactions: vec![make_legacy_tx(), make_eip1559_tx()],
        };
        let block = rpc_block_to_ethrex(&rpc_block).unwrap();
        assert_eq!(block.header.number, 10);
        assert_eq!(block.header.timestamp, 100_000_000);
        assert_eq!(block.header.gas_limit, 30_000_000);
        assert_eq!(block.body.transactions.len(), 2);
    }

    #[test]
    fn test_block_conversion_empty_txs() {
        let rpc_block = RpcBlock {
            header: make_block_header(),
            transactions: vec![],
        };
        let block = rpc_block_to_ethrex(&rpc_block).unwrap();
        assert!(block.body.transactions.is_empty());
    }

    #[test]
    fn test_rpc_log_conversion() {
        let rpc_log = RpcLog {
            address: Address::from_low_u64_be(0x42),
            topics: vec![H256::from([0x02; 32]), H256::from([0x03; 32])],
            data: vec![0x01, 0x02, 0x03],
        };
        let log = rpc_log_to_ethrex(&rpc_log);
        assert_eq!(log.address, Address::from_low_u64_be(0x42));
        assert_eq!(log.topics.len(), 2);
        assert_eq!(log.data.as_ref(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_build_env_no_base_fee() {
        let rpc_tx = make_legacy_tx();
        let mut header = make_block_header();
        header.base_fee_per_gas = None;
        let env = build_env_from_rpc(&rpc_tx, &header);
        assert_eq!(env.base_fee_per_gas, U256::zero());
        assert_eq!(env.gas_price, U256::from(2_000_000_000_u64));
    }
}
