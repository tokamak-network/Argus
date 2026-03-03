//! Post-hoc enrichment for SSTORE old_value fields.
//!
//! After replay completes, we walk the trace backward to fill in
//! `StorageWrite.old_value` for each SSTORE step. This avoids requiring
//! any modifications to the LEVM OpcodeRecorder trait.

use ethrex_common::{H256, U256};
use rustc_hash::FxHashMap;

use crate::types::{ReplayTrace, StepRecord};

const OP_SSTORE: u8 = 0x55;

/// Fill in `old_value` for all SSTORE storage writes in the trace.
///
/// Strategy:
/// 1. Scan forward through the trace, tracking (address, slot) → last_new_value.
/// 2. For each SSTORE, old_value = the previous write's new_value for the same
///    (address, slot), or `initial_value` from the provided map.
///
/// `initial_values` should contain pre-transaction storage values for slots
/// that are written. If not provided, old_value defaults to U256::zero().
pub fn enrich_storage_writes(
    trace: &mut ReplayTrace,
    initial_values: &FxHashMap<(ethrex_common::Address, H256), U256>,
) {
    // Track the last known value for each (address, slot)
    let mut slot_values: FxHashMap<(ethrex_common::Address, H256), U256> = FxHashMap::default();

    for step in &mut trace.steps {
        if step.opcode != OP_SSTORE {
            continue;
        }
        if let Some(writes) = &mut step.storage_writes {
            for write in writes {
                let key = (write.address, write.slot);
                // Look up the previous value: either from earlier SSTORE or initial state
                let old = slot_values
                    .get(&key)
                    .copied()
                    .or_else(|| initial_values.get(&key).copied())
                    .unwrap_or(U256::zero());
                write.old_value = old;
                // Track this write's new_value as the "current" value
                slot_values.insert(key, write.new_value);
            }
        }
    }
}

/// Collect all unique (address, slot) pairs from SSTORE steps.
/// Useful for pre-fetching initial storage values from the database.
pub fn collect_sstore_slots(steps: &[StepRecord]) -> Vec<(ethrex_common::Address, H256)> {
    let mut seen = FxHashMap::default();
    let mut result = Vec::new();
    for step in steps {
        if step.opcode != OP_SSTORE {
            continue;
        }
        if let Some(writes) = &step.storage_writes {
            for write in writes {
                let key = (write.address, write.slot);
                if seen.insert(key, ()).is_none() {
                    result.push(key);
                }
            }
        }
    }
    result
}
