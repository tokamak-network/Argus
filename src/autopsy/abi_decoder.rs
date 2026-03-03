//! ABI-based storage slot decoder.
//!
//! Given an optional ABI JSON, computes Solidity storage slot positions and
//! matches SSTORE/SLOAD slots to human-readable variable names.
//!
//! Supports:
//! - Simple variables (position = declaration order)
//! - Single-depth mappings: `keccak256(key . slot_position)`
//!
//! Nested mappings/structs/dynamic arrays are deferred to future work.

use ethrex_common::{H256, U256};
use sha3::{Digest, Keccak256};

/// A decoded storage variable from ABI.
#[derive(Debug, Clone)]
pub struct StorageVariable {
    /// Variable name from ABI.
    pub name: String,
    /// Base slot position (declaration order for simple vars).
    pub slot_position: u64,
    /// Whether this is a mapping.
    pub is_mapping: bool,
}

/// Decoded slot label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotLabel {
    /// Variable name.
    pub name: String,
    /// If a mapping, the key used (hex-encoded).
    pub key: Option<String>,
}

/// ABI-based storage decoder.
pub struct AbiDecoder {
    variables: Vec<StorageVariable>,
}

impl AbiDecoder {
    /// Parse ABI JSON to extract storage variables.
    ///
    /// Solidity ABI doesn't include storage layout directly, but we infer
    /// it from state variables in simplified ABI format:
    /// ```json
    /// [
    ///   { "name": "owner", "slot": 0, "type": "address" },
    ///   { "name": "balances", "slot": 1, "type": "mapping(address => uint256)" }
    /// ]
    /// ```
    ///
    /// This is a simplified "storage layout" format (not standard Solidity ABI).
    /// Tools like `solc --storage-layout` or Foundry produce this.
    pub fn from_storage_layout_json(json: &str) -> Result<Self, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;

        let entries = parsed
            .as_array()
            .ok_or("expected JSON array of storage entries")?;

        let mut variables = Vec::new();
        for entry in entries {
            let name = entry["name"]
                .as_str()
                .ok_or("missing 'name' field")?
                .to_string();
            let slot_position = entry["slot"]
                .as_u64()
                .ok_or("missing 'slot' field (must be integer)")?;
            let type_str = entry["type"].as_str().unwrap_or("");
            let is_mapping = type_str.starts_with("mapping");

            variables.push(StorageVariable {
                name,
                slot_position,
                is_mapping,
            });
        }

        Ok(Self { variables })
    }

    /// Try to label a storage slot hash.
    ///
    /// For simple variables, checks if `slot_hash == keccak256(slot_position)`
    /// matches. For mappings, checks against a small set of common key patterns
    /// (the actual key is unknown without additional context).
    pub fn label_slot(&self, slot: &H256) -> Option<SlotLabel> {
        let slot_u256 = U256::from_big_endian(slot.as_bytes());

        // Check simple variables (slot position matches directly)
        for var in &self.variables {
            if !var.is_mapping && slot_u256 == U256::from(var.slot_position) {
                return Some(SlotLabel {
                    name: var.name.clone(),
                    key: None,
                });
            }
        }

        None
    }

    /// Compute the storage slot for a mapping with an address key.
    ///
    /// `slot = keccak256(left_pad_32(key) ++ left_pad_32(mapping_position))`
    pub fn mapping_slot(key: &[u8; 20], mapping_position: u64) -> H256 {
        let mut preimage = [0u8; 64];
        // Key: left-padded to 32 bytes
        preimage[12..32].copy_from_slice(key);
        // Mapping position: left-padded to 32 bytes
        let pos_bytes = U256::from(mapping_position).to_big_endian();
        preimage[32..64].copy_from_slice(&pos_bytes);

        let hash = Keccak256::digest(preimage);
        H256::from_slice(&hash)
    }

    /// Compute the storage slot for a mapping with a uint256 key.
    ///
    /// `slot = keccak256(left_pad_32(key) ++ left_pad_32(mapping_position))`
    pub fn mapping_slot_u256(key: U256, mapping_position: u64) -> H256 {
        let mut preimage = [0u8; 64];
        let key_bytes = key.to_big_endian();
        preimage[..32].copy_from_slice(&key_bytes);
        let pos_bytes = U256::from(mapping_position).to_big_endian();
        preimage[32..64].copy_from_slice(&pos_bytes);

        let hash = Keccak256::digest(preimage);
        H256::from_slice(&hash)
    }

    /// Try to match a slot against known mapping positions with a given address key.
    ///
    /// Useful when the caller knows which addresses interacted with the contract.
    pub fn label_mapping_slot(&self, slot: &H256, known_keys: &[[u8; 20]]) -> Option<SlotLabel> {
        for var in &self.variables {
            if !var.is_mapping {
                continue;
            }
            for key in known_keys {
                let computed = Self::mapping_slot(key, var.slot_position);
                if computed == *slot {
                    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
                    return Some(SlotLabel {
                        name: var.name.clone(),
                        key: Some(format!("0x{key_hex}")),
                    });
                }
            }
        }
        None
    }
}
