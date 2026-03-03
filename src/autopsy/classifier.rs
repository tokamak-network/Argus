//! Attack pattern classifier.
//!
//! Analyzes execution traces to detect common DeFi attack patterns:
//! reentrancy, flash loans, price manipulation, and access control bypasses.

use ethrex_common::{Address, U256};
use rustc_hash::FxHashMap;

use crate::types::StepRecord;

use super::types::{AttackPattern, DetectedPattern};

// Opcode constants
const OP_SLOAD: u8 = 0x54;
const OP_SSTORE: u8 = 0x55;
const OP_CALL: u8 = 0xF1;
const OP_CALLCODE: u8 = 0xF2;
const OP_DELEGATECALL: u8 = 0xF4;
const OP_STATICCALL: u8 = 0xFA;
const OP_CALLER: u8 = 0x33;
const OP_LOG3: u8 = 0xA3;

/// Stateless attack pattern classifier.
pub struct AttackClassifier;

impl AttackClassifier {
    /// Analyze a trace and return all detected attack patterns.
    pub fn classify(steps: &[StepRecord]) -> Vec<AttackPattern> {
        Self::classify_with_confidence(steps)
            .into_iter()
            .map(|d| d.pattern)
            .collect()
    }

    /// Analyze with confidence scores and evidence chains.
    pub fn classify_with_confidence(steps: &[StepRecord]) -> Vec<DetectedPattern> {
        let mut detected = Vec::new();

        for pattern in Self::detect_reentrancy(steps) {
            let (confidence, evidence) = Self::score_reentrancy(&pattern, steps);
            detected.push(DetectedPattern {
                pattern,
                confidence,
                evidence,
            });
        }
        for pattern in Self::detect_flash_loan(steps) {
            let (confidence, evidence) = Self::score_flash_loan(&pattern, steps);
            detected.push(DetectedPattern {
                pattern,
                confidence,
                evidence,
            });
        }
        for pattern in Self::detect_price_manipulation(steps) {
            let (confidence, evidence) = Self::score_price_manipulation(&pattern);
            detected.push(DetectedPattern {
                pattern,
                confidence,
                evidence,
            });
        }
        for pattern in Self::detect_access_control_bypass(steps) {
            let (confidence, evidence) = Self::score_access_control(&pattern, steps);
            detected.push(DetectedPattern {
                pattern,
                confidence,
                evidence,
            });
        }

        detected
    }

    /// Detect reentrancy: CALL at depth D to address A, then steps at depth > D
    /// with same code_address A, followed by SSTORE after re-entry.
    fn detect_reentrancy(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Build a list of external calls with their targets and depths
        let calls: Vec<(usize, Address, usize)> = steps
            .iter()
            .filter(|s| is_call_opcode(s.opcode))
            .filter_map(|s| {
                // For CALL/CALLCODE, target address is stack[1] (to)
                let target = extract_call_target(s)?;
                Some((s.step_index, target, s.depth))
            })
            .collect();

        for &(call_idx, _target, call_depth) in &calls {
            // The caller (potential victim) is the contract that made this CALL
            let caller_address = steps
                .get(call_idx)
                .map(|s| s.code_address)
                .unwrap_or(Address::zero());

            // Look for re-entry: a subsequent CALL at deeper depth that
            // targets the original caller (victim) address
            let reentry_step = calls.iter().find(|&&(idx, tgt, depth)| {
                idx > call_idx && depth > call_depth && tgt == caller_address
            });

            if let Some(&(reentry_idx, _, _)) = reentry_step {
                // Look for SSTORE after re-entry in the victim contract
                let sstore_after = steps[reentry_idx..]
                    .iter()
                    .find(|s| s.opcode == OP_SSTORE && s.code_address == caller_address);

                if let Some(sstore) = sstore_after {
                    patterns.push(AttackPattern::Reentrancy {
                        target_contract: caller_address,
                        reentrant_call_step: reentry_idx,
                        state_modified_step: sstore.step_index,
                        call_depth_at_entry: call_depth,
                    });
                }
            }
        }

        patterns
    }

    /// Detect flash loan patterns using three complementary strategies:
    /// 1. ETH value: large CALL value early → matching repay late
    /// 2. ERC-20: matching Transfer events (same token, to/from same address)
    /// 3. Callback: depth sandwich pattern (entry → deep operations → exit)
    fn detect_flash_loan(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();
        let total = steps.len();
        if total < 4 {
            return patterns;
        }

        // === Strategy 1: ETH value-based flash loan ===
        let first_quarter = total / 4;
        let last_quarter_start = total - (total / 4);

        let borrows: Vec<(usize, U256)> = steps[..first_quarter.min(steps.len())]
            .iter()
            .filter_map(|s| {
                let value = s.call_value.as_ref()?;
                if *value > U256::zero() {
                    Some((s.step_index, *value))
                } else {
                    None
                }
            })
            .collect();

        for &(borrow_idx, borrow_amount) in &borrows {
            let repay = steps[last_quarter_start..].iter().find(|s| {
                if let Some(value) = &s.call_value {
                    *value >= borrow_amount && s.step_index > borrow_idx
                } else {
                    false
                }
            });

            if let Some(repay_step) = repay {
                patterns.push(AttackPattern::FlashLoan {
                    borrow_step: borrow_idx,
                    borrow_amount,
                    repay_step: repay_step.step_index,
                    repay_amount: repay_step.call_value.unwrap_or(U256::zero()),
                    provider: None,
                    token: None,
                });
            }
        }

        // === Strategy 2: ERC-20 token-based flash loan ===
        patterns.extend(Self::detect_flash_loan_erc20(steps));

        // === Strategy 3: Callback-based flash loan ===
        patterns.extend(Self::detect_flash_loan_callback(steps));

        patterns
    }

    /// Detect ERC-20 flash loans: matching Transfer events where the same token
    /// is sent TO and later FROM the same address.
    fn detect_flash_loan_erc20(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Collect all ERC-20 Transfer events
        let transfers: Vec<Erc20Transfer> = steps
            .iter()
            .filter(|s| s.opcode == OP_LOG3)
            .filter_map(|s| {
                let topics = s.log_topics.as_ref()?;
                if topics.len() < 3 {
                    return None;
                }
                if !is_transfer_topic(&topics[0]) {
                    return None;
                }
                let from = address_from_topic(&topics[1]);
                let to = address_from_topic(&topics[2]);
                let token = s.code_address;
                Some(Erc20Transfer {
                    step_index: s.step_index,
                    token,
                    from,
                    to,
                })
            })
            .collect();

        // For each incoming transfer (token → address X), look for a matching
        // outgoing transfer (address X → token) later in the trace.
        let total = steps.len();
        let half = total / 2;

        for incoming in &transfers {
            if incoming.step_index >= half {
                continue; // Only look at first half for borrows
            }
            let recipient = incoming.to;
            let token = incoming.token;

            // Look for matching outgoing transfer in second half
            let outgoing = transfers.iter().find(|t| {
                t.step_index > incoming.step_index
                    && t.step_index >= half
                    && t.token == token
                    && t.from == recipient
            });

            if let Some(repay) = outgoing {
                patterns.push(AttackPattern::FlashLoan {
                    borrow_step: incoming.step_index,
                    borrow_amount: U256::zero(), // Amount in log data, not captured
                    repay_step: repay.step_index,
                    repay_amount: U256::zero(),
                    provider: Some(incoming.from),
                    token: Some(token),
                });
            }
        }

        patterns
    }

    /// Detect callback-based flash loans by analyzing the depth profile.
    ///
    /// Flash loan callbacks have a distinctive depth pattern:
    /// - Entry at shallow depth (the top-level call)
    /// - CALL to flash loan provider
    /// - Provider calls back at deeper depth (the callback)
    /// - Most operations execute at this deeper depth
    /// - Return to shallow depth
    ///
    /// If >60% of operations happen at depth > entry_depth + 1, this indicates
    /// a callback wrapper pattern typical of flash loans.
    fn detect_flash_loan_callback(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();
        let total = steps.len();
        if total < 10 {
            return patterns;
        }

        let entry_depth = steps[0].depth;

        // Count steps per depth
        let mut depth_counts: FxHashMap<usize, usize> = FxHashMap::default();
        for step in steps {
            *depth_counts.entry(step.depth).or_default() += 1;
        }

        // Count steps deeper than entry_depth + 1 (inside the callback)
        let deep_steps: usize = depth_counts
            .iter()
            .filter(|&(&d, _)| d > entry_depth + 1)
            .map(|(_, &c)| c)
            .sum();

        let deep_ratio = deep_steps as f64 / total as f64;

        // If >60% of steps are deep, this is a callback pattern
        if deep_ratio < 0.6 {
            return patterns;
        }

        // Find the CALL that initiates the depth transition (flash loan call)
        let flash_loan_call = steps
            .iter()
            .find(|s| is_call_opcode(s.opcode) && s.depth == entry_depth);

        // Find the provider: the target of that CALL
        let provider = flash_loan_call.and_then(extract_call_target);

        // Find the callback entry: first step at depth > entry_depth + 1
        let callback_entry = steps.iter().find(|s| s.depth > entry_depth + 1);

        // Find the last deep step (approximate end of callback)
        let callback_exit = steps.iter().rev().find(|s| s.depth > entry_depth + 1);

        if let (Some(entry), Some(exit)) = (callback_entry, callback_exit) {
            // Count state-modifying ops inside the callback to confirm it's non-trivial
            let inner_sstores = steps
                .iter()
                .filter(|s| {
                    s.depth > entry_depth + 1
                        && matches!(s.opcode, OP_SSTORE | OP_CALL | OP_DELEGATECALL)
                })
                .count();

            if inner_sstores >= 1 {
                patterns.push(AttackPattern::FlashLoan {
                    borrow_step: flash_loan_call
                        .map(|s| s.step_index)
                        .unwrap_or(entry.step_index),
                    borrow_amount: U256::zero(),
                    repay_step: exit.step_index,
                    repay_amount: U256::zero(),
                    provider,
                    token: None,
                });
            }
        }

        patterns
    }

    /// Detect price manipulation: STATICCALL to same address twice with
    /// a LOG3 Transfer event between them (indicating a swap).
    fn detect_price_manipulation(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Find pairs of STATICCALL to same address with a Transfer event between
        let static_calls: Vec<(usize, Address)> = steps
            .iter()
            .filter(|s| s.opcode == OP_STATICCALL)
            .filter_map(|s| {
                let target = extract_call_target_static(s)?;
                Some((s.step_index, target))
            })
            .collect();

        // Find LOG3 Transfer events (ERC-20 Transfer topic)
        let transfers: Vec<usize> = steps
            .iter()
            .filter(|s| s.opcode == OP_LOG3 && has_transfer_topic(s))
            .map(|s| s.step_index)
            .collect();

        for i in 0..static_calls.len() {
            let (read1_idx, oracle_addr) = static_calls[i];

            // Find a transfer event after this read
            let swap_idx = transfers.iter().find(|&&t| t > read1_idx);
            let Some(&swap_step) = swap_idx else {
                continue;
            };

            // Find second read to same oracle after the swap
            let read2 = static_calls[i + 1..]
                .iter()
                .find(|&&(idx, addr)| idx > swap_step && addr == oracle_addr);

            if let Some(&(read2_idx, _)) = read2 {
                let delta = Self::estimate_price_delta(steps, oracle_addr, read1_idx, read2_idx);
                patterns.push(AttackPattern::PriceManipulation {
                    oracle_read_before: read1_idx,
                    swap_step,
                    oracle_read_after: read2_idx,
                    price_delta_percent: delta,
                });
            }
        }

        patterns
    }

    /// Estimate price delta between two oracle reads by examining SLOAD values.
    ///
    /// Looks for SLOAD operations in the oracle contract near each STATICCALL.
    /// The return value of SLOAD appears at stack_top[0] of the *next* step.
    /// If the same slot is read with different values → compute percentage delta.
    /// Returns -1.0 if values cannot be compared (no SLOAD data found).
    fn estimate_price_delta(
        steps: &[StepRecord],
        oracle_addr: Address,
        read1_idx: usize,
        read2_idx: usize,
    ) -> f64 {
        // Collect SLOAD results near the first read (within 20 steps after read1)
        let sloads_before =
            Self::collect_sload_results(steps, oracle_addr, read1_idx, read1_idx + 20);
        // Collect SLOAD results near the second read (within 20 steps after read2)
        let sloads_after =
            Self::collect_sload_results(steps, oracle_addr, read2_idx, read2_idx + 20);

        if sloads_before.is_empty() || sloads_after.is_empty() {
            return -1.0; // Cannot determine — no SLOAD data
        }

        // Match SLOAD results by slot key — if same slot read twice with different values
        for (slot_before, value_before) in &sloads_before {
            for (slot_after, value_after) in &sloads_after {
                if slot_before != slot_after {
                    continue;
                }
                if *value_before == *value_after {
                    return 0.0; // Same value — no price change
                }
                // Compute delta: |new - old| / old * 100
                if value_before.is_zero() {
                    return -1.0; // Division by zero — cannot compute
                }
                // Use f64 for percentage (sufficient precision for reporting)
                let old_f = value_before.low_u128() as f64;
                let new_f = value_after.low_u128() as f64;
                if old_f == 0.0 {
                    return -1.0;
                }
                return ((new_f - old_f).abs() / old_f) * 100.0;
            }
        }

        -1.0 // No matching slots found
    }

    /// Collect SLOAD return values for a given contract within a step range.
    ///
    /// Returns (slot_key, return_value) pairs. The return value is read from
    /// the stack_top[0] of the step immediately following the SLOAD.
    fn collect_sload_results(
        steps: &[StepRecord],
        target_addr: Address,
        from_idx: usize,
        to_idx: usize,
    ) -> Vec<(U256, U256)> {
        let clamped_to = to_idx.min(steps.len());
        let mut results = Vec::new();

        for i in from_idx..clamped_to {
            let step = &steps[i];
            if step.opcode != OP_SLOAD || step.code_address != target_addr {
                continue;
            }
            // SLOAD pre-state stack: stack_top[0] = slot key
            let Some(slot_key) = step.stack_top.first().copied() else {
                continue;
            };
            // Return value appears at stack_top[0] of the next step
            let Some(next_step) = steps.get(i + 1) else {
                continue;
            };
            let Some(return_value) = next_step.stack_top.first().copied() else {
                continue;
            };
            results.push((slot_key, return_value));
        }

        results
    }

    /// Detect access control bypass: SSTORE without CALLER (0x33) check
    /// in the same call frame depth.
    fn detect_access_control_bypass(steps: &[StepRecord]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Group steps by (code_address, depth) to represent call frames
        let mut frames: FxHashMap<(Address, usize), FrameInfo> = FxHashMap::default();

        for step in steps {
            let key = (step.code_address, step.depth);
            let frame = frames.entry(key).or_insert_with(|| FrameInfo {
                has_caller_check: false,
                sstore_steps: Vec::new(),
            });

            if step.opcode == OP_CALLER {
                frame.has_caller_check = true;
            }
            if step.opcode == OP_SSTORE {
                frame.sstore_steps.push(step.step_index);
            }
        }

        // Flag frames with SSTORE but no CALLER check
        for ((contract, _depth), frame) in &frames {
            if !frame.has_caller_check && !frame.sstore_steps.is_empty() {
                for &sstore_step in &frame.sstore_steps {
                    patterns.push(AttackPattern::AccessControlBypass {
                        sstore_step,
                        contract: *contract,
                    });
                }
            }
        }

        patterns
    }

    // ── Confidence Scoring ────────────────────────────────────────────

    /// Score reentrancy pattern.
    /// High: re-entry + SSTORE + value transfer
    /// Medium: re-entry + SSTORE only
    /// Low: re-entry only (no SSTORE)
    fn score_reentrancy(pattern: &AttackPattern, steps: &[StepRecord]) -> (f64, Vec<String>) {
        let AttackPattern::Reentrancy {
            target_contract,
            reentrant_call_step,
            state_modified_step,
            ..
        } = pattern
        else {
            return (0.0, vec![]);
        };

        let mut evidence = vec![
            format!("Re-entrant call at step {reentrant_call_step}"),
            format!("State modified at step {state_modified_step}"),
        ];

        let has_sstore = *state_modified_step > 0;
        let has_value_transfer = steps.iter().any(|s| {
            s.step_index >= *reentrant_call_step
                && s.code_address == *target_contract
                && s.call_value.is_some_and(|v| v > U256::zero())
        });

        if has_value_transfer {
            evidence.push("Value transfer during re-entry".to_string());
        }

        let confidence = if has_sstore && has_value_transfer {
            0.9
        } else if has_sstore {
            0.7
        } else {
            0.4
        };

        (confidence, evidence)
    }

    /// Score flash loan pattern.
    /// High: borrow + repay + inner state modification
    /// Medium: callback depth pattern with state mods
    /// Low: depth profile only
    fn score_flash_loan(pattern: &AttackPattern, steps: &[StepRecord]) -> (f64, Vec<String>) {
        let AttackPattern::FlashLoan {
            borrow_step,
            repay_step,
            borrow_amount,
            provider,
            token,
            ..
        } = pattern
        else {
            return (0.0, vec![]);
        };

        let mut evidence = vec![format!(
            "Borrow at step {borrow_step}, repay at step {repay_step}"
        )];

        let has_amount = *borrow_amount > U256::zero();
        if has_amount {
            evidence.push(format!("Borrow amount: {borrow_amount}"));
        }

        let has_provider = provider.is_some();
        if has_provider {
            evidence.push(format!("Provider: 0x{:x}", provider.unwrap()));
        }

        let has_token = token.is_some();
        if has_token {
            evidence.push("ERC-20 token transfer detected".to_string());
        }

        // Check for inner state modifications between borrow and repay
        let inner_sstores = steps
            .iter()
            .filter(|s| {
                s.step_index > *borrow_step && s.step_index < *repay_step && s.opcode == OP_SSTORE
            })
            .count();

        if inner_sstores > 0 {
            evidence.push(format!("{inner_sstores} SSTORE(s) inside callback"));
        }

        let confidence = if has_amount && inner_sstores > 0 {
            0.9
        } else if has_provider && inner_sstores > 0 {
            0.8
        } else if inner_sstores > 0 {
            0.6
        } else {
            0.4
        };

        (confidence, evidence)
    }

    /// Score price manipulation pattern.
    /// High: oracle read-swap-read + delta > 5%
    /// Medium: pattern detected without significant delta
    /// Low: partial pattern match
    fn score_price_manipulation(pattern: &AttackPattern) -> (f64, Vec<String>) {
        let AttackPattern::PriceManipulation {
            oracle_read_before,
            swap_step,
            oracle_read_after,
            price_delta_percent,
        } = pattern
        else {
            return (0.0, vec![]);
        };

        let mut evidence = vec![
            format!("Oracle read before swap at step {oracle_read_before}"),
            format!("Swap at step {swap_step}"),
            format!("Oracle read after swap at step {oracle_read_after}"),
        ];

        if *price_delta_percent >= 0.0 {
            evidence.push(format!("Price delta: {price_delta_percent:.1}%"));
        }

        let confidence = if *price_delta_percent > 5.0 {
            0.9
        } else if *price_delta_percent >= 0.0 {
            0.6
        } else {
            // -1.0 = unknown delta
            0.4
        };

        (confidence, evidence)
    }

    /// Score access control bypass.
    /// Medium: SSTORE without CALLER check
    /// Low: heuristic only
    fn score_access_control(pattern: &AttackPattern, _steps: &[StepRecord]) -> (f64, Vec<String>) {
        let AttackPattern::AccessControlBypass {
            sstore_step,
            contract,
        } = pattern
        else {
            return (0.0, vec![]);
        };

        let evidence = vec![
            format!("SSTORE at step {sstore_step} without CALLER check"),
            format!("Contract: 0x{contract:x}"),
        ];

        // Access control bypass is inherently heuristic
        (0.5, evidence)
    }
}

struct FrameInfo {
    has_caller_check: bool,
    sstore_steps: Vec<usize>,
}

fn is_call_opcode(op: u8) -> bool {
    matches!(op, OP_CALL | OP_CALLCODE | OP_DELEGATECALL | OP_STATICCALL)
}

/// Extract target address from CALL/CALLCODE stack: stack[1] = to address.
fn extract_call_target(step: &StepRecord) -> Option<Address> {
    let val = step.stack_top.get(1)?;
    let bytes = val.to_big_endian();
    Some(Address::from_slice(&bytes[12..]))
}

/// Extract target address from STATICCALL/DELEGATECALL stack: stack[1] = to address.
fn extract_call_target_static(step: &StepRecord) -> Option<Address> {
    let val = step.stack_top.get(1)?;
    let bytes = val.to_big_endian();
    Some(Address::from_slice(&bytes[12..]))
}

/// Check if a LOG step has the ERC-20 Transfer event topic.
fn has_transfer_topic(step: &StepRecord) -> bool {
    if let Some(topics) = &step.log_topics {
        topics.first().is_some_and(is_transfer_topic)
    } else {
        false
    }
}

/// Check if a topic hash matches the ERC-20 Transfer event signature.
fn is_transfer_topic(topic: &ethrex_common::H256) -> bool {
    let b = topic.as_bytes();
    b[0] == 0xdd && b[1] == 0xf2 && b[2] == 0x52 && b[3] == 0xad
}

/// Extract an address from a 32-byte topic (last 20 bytes).
fn address_from_topic(topic: &ethrex_common::H256) -> Address {
    Address::from_slice(&topic.as_bytes()[12..])
}

/// Parsed ERC-20 Transfer event.
struct Erc20Transfer {
    step_index: usize,
    token: Address,
    from: Address,
    to: Address,
}
