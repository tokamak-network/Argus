//! FeatureVector extraction and reentrancy depth detection.

use std::collections::HashSet;

use ethrex_common::U256;

use crate::types::StepRecord;

use super::{
    OP_CALL, OP_CALLCODE, OP_CREATE, OP_CREATE2, OP_DELEGATECALL, OP_LOG0, OP_LOG4, OP_REVERT,
    OP_SELFDESTRUCT, OP_SLOAD, OP_SSTORE, OP_STATICCALL,
};

/// Numerical feature vector extracted from an execution trace.
///
/// All fields use `f64` for compatibility with the anomaly model's z-score math.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FeatureVector {
    pub total_steps: f64,
    pub unique_addresses: f64,
    pub max_call_depth: f64,
    pub sstore_count: f64,
    pub sload_count: f64,
    pub call_count: f64,
    pub delegatecall_count: f64,
    pub staticcall_count: f64,
    pub create_count: f64,
    pub selfdestruct_count: f64,
    pub log_count: f64,
    pub revert_count: f64,
    pub reentrancy_depth: f64,
    pub eth_transferred_wei: f64,
    pub gas_ratio: f64,
    pub calldata_entropy: f64,
}

impl FeatureVector {
    /// Extract a feature vector from an execution trace.
    pub fn from_trace(steps: &[StepRecord], gas_used: u64, gas_limit: u64) -> Self {
        let mut addresses = HashSet::new();
        let mut max_depth: usize = 0;
        let mut sstore = 0u32;
        let mut sload = 0u32;
        let mut call = 0u32;
        let mut delegatecall = 0u32;
        let mut staticcall = 0u32;
        let mut create = 0u32;
        let mut selfdestruct = 0u32;
        let mut log = 0u32;
        let mut revert = 0u32;
        let mut eth_total: f64 = 0.0;

        for step in steps {
            addresses.insert(step.code_address);
            if step.depth > max_depth {
                max_depth = step.depth;
            }
            match step.opcode {
                OP_SLOAD => sload += 1,
                OP_SSTORE => sstore += 1,
                OP_CALL | OP_CALLCODE => {
                    call += 1;
                    if let Some(val) = &step.call_value
                        && *val > U256::zero()
                    {
                        eth_total += val.low_u128() as f64;
                    }
                }
                OP_DELEGATECALL => delegatecall += 1,
                OP_STATICCALL => staticcall += 1,
                OP_CREATE | OP_CREATE2 => create += 1,
                OP_SELFDESTRUCT => selfdestruct += 1,
                OP_REVERT => revert += 1,
                op if (OP_LOG0..=OP_LOG4).contains(&op) => log += 1,
                _ => {}
            }
        }

        let gas_ratio = if gas_limit > 0 {
            gas_used as f64 / gas_limit as f64
        } else {
            0.0
        };

        // Reentrancy depth: max number of times we see the same address at
        // increasing call depths within the trace.
        let reentrancy_depth = detect_reentrancy_depth(steps);

        Self {
            total_steps: steps.len() as f64,
            unique_addresses: addresses.len() as f64,
            max_call_depth: max_depth as f64,
            sstore_count: sstore as f64,
            sload_count: sload as f64,
            call_count: call as f64,
            delegatecall_count: delegatecall as f64,
            staticcall_count: staticcall as f64,
            create_count: create as f64,
            selfdestruct_count: selfdestruct as f64,
            log_count: log as f64,
            revert_count: revert as f64,
            reentrancy_depth: reentrancy_depth as f64,
            eth_transferred_wei: eth_total,
            gas_ratio,
            calldata_entropy: 0.0, // placeholder — calldata not in trace
        }
    }
}

/// Detect reentrancy depth by counting re-entries to the same address at
/// increasing call depths.
pub fn detect_reentrancy_depth(steps: &[StepRecord]) -> u32 {
    use std::collections::HashMap;

    // Track the first depth at which each address appears, then count
    // how many times an address appears at a deeper level than its first.
    let mut first_depth: HashMap<ethrex_common::Address, usize> = HashMap::new();
    let mut max_reentry = 0u32;

    for step in steps {
        if matches!(
            step.opcode,
            OP_CALL | OP_CALLCODE | OP_DELEGATECALL | OP_STATICCALL
        ) {
            let addr = step.code_address;
            match first_depth.get(&addr) {
                Some(&first) if step.depth > first => {
                    let depth = (step.depth - first) as u32;
                    if depth > max_reentry {
                        max_reentry = depth;
                    }
                }
                None => {
                    first_depth.insert(addr, step.depth);
                }
                _ => {}
            }
        }
    }

    max_reentry
}
