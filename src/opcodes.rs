//! EVM opcode constants used across modules.
//!
//! Single source of truth — prevents duplication across recorder, autopsy,
//! sentinel pipeline, and AI context extractor.

pub const OP_CALLER: u8 = 0x33;
pub const OP_SLOAD: u8 = 0x54;
pub const OP_SSTORE: u8 = 0x55;
pub const OP_LOG0: u8 = 0xA0;
pub const OP_LOG3: u8 = 0xA3;
pub const OP_LOG4: u8 = 0xA4;
pub const OP_CREATE: u8 = 0xF0;
pub const OP_CALL: u8 = 0xF1;
pub const OP_CALLCODE: u8 = 0xF2;
pub const OP_RETURN: u8 = 0xF3;
pub const OP_DELEGATECALL: u8 = 0xF4;
pub const OP_CREATE2: u8 = 0xF5;
pub const OP_STATICCALL: u8 = 0xFA;
pub const OP_REVERT: u8 = 0xFD;
pub const OP_SELFDESTRUCT: u8 = 0xFF;
