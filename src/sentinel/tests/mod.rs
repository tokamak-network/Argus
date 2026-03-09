//! Tests for the Sentinel pre-filter engine and deep analysis types.

use bytes::Bytes;
use ethrex_common::types::{
    BlockHeader, LegacyTransaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};

use super::pre_filter::PreFilter;
use super::types::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

pub(super) fn make_receipt(succeeded: bool, cumulative_gas: u64, logs: Vec<Log>) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

pub(super) fn make_log(address: Address, topics: Vec<H256>, data: Bytes) -> Log {
    Log {
        address,
        topics,
        data,
    }
}

pub(super) fn make_tx_call(to: Address, value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Call(to),
        value,
        ..Default::default()
    })
}

pub(super) fn make_tx_create(value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Create,
        value,
        ..Default::default()
    })
}

pub(super) fn make_header(number: u64) -> BlockHeader {
    BlockHeader {
        number,
        ..Default::default()
    }
}

pub(super) fn random_address(seed: u8) -> Address {
    Address::from_slice(&[seed; 20])
}

/// Build an H256 topic with the given 4-byte prefix.
pub(super) fn topic_with_prefix(prefix: [u8; 4]) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&prefix);
    H256::from(bytes)
}

/// Build a Transfer(address,address,uint256) topic.
pub(super) fn transfer_topic() -> H256 {
    topic_with_prefix([0xdd, 0xf2, 0x52, 0xad])
}

/// Build a mock ERC-20 Transfer log with 3 topics.
pub(super) fn make_erc20_transfer_log(from: Address, to: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..32].copy_from_slice(from.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..32].copy_from_slice(to.as_bytes());

    make_log(
        random_address(0xEE),
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]), // amount
    )
}

pub(super) fn aave_v2_pool() -> Address {
    let bytes = hex::decode("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9").unwrap();
    Address::from_slice(&bytes)
}

pub(super) fn uniswap_v3_router() -> Address {
    let bytes = hex::decode("E592427A0AEce92De3Edee1F18E0157C05861564").unwrap();
    Address::from_slice(&bytes)
}

pub(super) fn chainlink_eth_usd() -> Address {
    let bytes = hex::decode("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419").unwrap();
    Address::from_slice(&bytes)
}

pub(super) fn one_eth() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

pub(super) fn balancer_vault() -> Address {
    let bytes = hex::decode("BA12222222228d8Ba445958a75a0704d566BF2C8").unwrap();
    Address::from_slice(&bytes)
}

mod alert_tests;
mod pipeline_tests;
mod prefilter_benchmark;
mod prefilter_scoring_tests;
mod prefilter_tests;
mod rpc_service_tests;
mod service_tests;
mod whitelist_tests;
