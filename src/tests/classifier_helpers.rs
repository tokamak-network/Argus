//! Shared test helpers for classifier tests.
//!
//! Provides step builders and address utilities used by both
//! `classifier_diagnostic` and `classifier_validation_tests`.

use crate::types::{StepRecord, StorageWrite};
use ethrex_common::{Address, H256, U256};

/// Create an Address from a low u64 identifier.
pub fn addr(id: u64) -> Address {
    Address::from_low_u64_be(id)
}

/// Balancer V2 Vault address (abbreviated).
pub fn balancer_vault() -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = 0xBA;
    bytes[1] = 0x12;
    bytes[2] = 0x22;
    bytes[3] = 0x22;
    Address::from_slice(&bytes)
}

/// Build an H256 storage slot from a u64 identifier.
pub fn slot(n: u64) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&n.to_be_bytes());
    H256::from(bytes)
}

/// ERC-20 Transfer event topic (first 4 bytes of keccak256("Transfer(address,address,uint256)")).
pub fn transfer_topic() -> H256 {
    let mut bytes = [0u8; 32];
    bytes[0] = 0xdd;
    bytes[1] = 0xf2;
    bytes[2] = 0x52;
    bytes[3] = 0xad;
    H256::from(bytes)
}

/// Pack an Address into a 32-byte topic (right-aligned, last 20 bytes).
pub fn addr_to_topic(a: Address) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(a.as_bytes());
    H256::from(bytes)
}

/// Build a minimal StepRecord at the given index, opcode, depth, and code_address.
pub fn make_step(index: usize, opcode: u8, depth: usize, code_address: Address) -> StepRecord {
    StepRecord {
        step_index: index,
        pc: index * 2,
        opcode,
        depth,
        gas_remaining: 1_000_000 - (index as i64 * 10),
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

/// Build a CALL step (opcode 0xF1) with the given value transfer.
///
/// `call_value` is `Some(value)` only when `value > 0`; this mirrors
/// how the production recorder populates the field.
pub fn make_call_step(
    index: usize,
    depth: usize,
    from: Address,
    to: Address,
    value: U256,
) -> StepRecord {
    let to_u256 = U256::from_big_endian(to.as_bytes());
    StepRecord {
        opcode: 0xF1, // CALL
        stack_top: vec![U256::from(100_000), to_u256, value],
        stack_depth: 7,
        code_address: from,
        call_value: if value > U256::zero() {
            Some(value)
        } else {
            None
        },
        ..make_step(index, 0xF1, depth, from)
    }
}

/// Build an SSTORE step with explicit slot and new_value.
pub fn make_sstore_step(
    index: usize,
    depth: usize,
    address: Address,
    s: H256,
    new_value: U256,
) -> StepRecord {
    StepRecord {
        opcode: 0x55,
        stack_top: vec![],
        stack_depth: 2,
        storage_writes: Some(vec![StorageWrite {
            address,
            slot: s,
            old_value: U256::zero(),
            new_value,
        }]),
        ..make_step(index, 0x55, depth, address)
    }
}

/// Shorthand: SSTORE with default slot(0) and value 42.
pub fn make_sstore_step_simple(index: usize, depth: usize, contract: Address) -> StepRecord {
    make_sstore_step(index, depth, contract, H256::zero(), U256::from(42))
}

/// Build a LOG3 step emitting an ERC-20 Transfer event.
///
/// `log_data` encodes 100 tokens as a uint256 (non-zero amount).
pub fn make_log3_transfer(
    index: usize,
    depth: usize,
    token: Address,
    from: Address,
    to: Address,
) -> StepRecord {
    let mut amount_bytes = [0u8; 32];
    amount_bytes[16..].copy_from_slice(&100u128.to_be_bytes());
    StepRecord {
        opcode: 0xA3,
        log_topics: Some(vec![
            transfer_topic(),
            addr_to_topic(from),
            addr_to_topic(to),
        ]),
        log_data: Some(amount_bytes.to_vec()),
        ..make_step(index, 0xA3, depth, token)
    }
}
