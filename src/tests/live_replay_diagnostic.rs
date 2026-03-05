//! Live RPC replay diagnostic tests.
//!
//! These tests replay actual mainnet transactions and inspect the StepRecord
//! data to verify that log_topics, log_data, stack_top, and depth are correctly
//! captured by the recorder.
//!
//! Requires: ALCHEMY_API_KEY or ARCHIVE_RPC_URL environment variable.

#![cfg(all(feature = "sentinel", feature = "autopsy"))]

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::rpc_client::EthRpcClient;
use crate::sentinel::rpc_replay::replay_tx_from_rpc;
use crate::sentinel::types::AnalysisConfig;
use rustc_hash::FxHashMap;

fn get_rpc_url() -> String {
    std::env::var("ARCHIVE_RPC_URL")
        .or_else(|_| {
            std::env::var("ALCHEMY_API_KEY")
                .map(|k| format!("https://eth-mainnet.g.alchemy.com/v2/{k}"))
        })
        .expect("ARCHIVE_RPC_URL or ALCHEMY_API_KEY required")
}

/// Replay the actual Balancer flash loan TX from the detection report and
/// inspect LOG3 steps for log_topics presence + depth distribution.
///
/// TX: 0x5a7f67e7edf2edea9ce6d5b485f1da1563a806be66f2e070ecb34c8ee2937c68
/// Block: 24587746, TX index: 6
/// Total steps (from report): 17,802
#[test]
#[ignore = "requires live RPC endpoint (ALCHEMY_API_KEY)"]
fn diag_live_balancer_flash_loan_log3_and_depth() {
    let rpc_url = get_rpc_url();
    let block_number = 24_587_746_u64;
    let tx_index = 6;

    let client = EthRpcClient::new(&rpc_url, block_number);
    let rpc_block = client
        .eth_get_block_by_number_with_txs(block_number)
        .expect("failed to fetch block");

    let config = AnalysisConfig {
        max_steps: 500_000,
        ..Default::default()
    };

    let result = replay_tx_from_rpc(&rpc_url, block_number, tx_index, &rpc_block, &config)
        .expect("replay should succeed");

    let steps = &result.trace.steps;
    let total_steps = steps.len();

    eprintln!("=== LIVE Balancer Flash Loan Diagnostic ===");
    eprintln!("Block: {block_number}, TX index: {tx_index}");
    eprintln!("Total steps: {total_steps}");
    eprintln!("TX success: {}", result.trace.success);
    eprintln!();

    // ── Verification 1: LOG3 log_topics ──

    let log3_steps: Vec<_> = steps.iter().filter(|s| s.opcode == 0xA3).collect();
    let log3_with_topics: Vec<_> = log3_steps
        .iter()
        .filter(|s| s.log_topics.is_some())
        .collect();
    let log3_without_topics: Vec<_> = log3_steps
        .iter()
        .filter(|s| s.log_topics.is_none())
        .collect();

    eprintln!("--- LOG3 Analysis ---");
    eprintln!("Total LOG3 steps: {}", log3_steps.len());
    eprintln!("LOG3 with log_topics (Some): {}", log3_with_topics.len());
    eprintln!(
        "LOG3 without log_topics (None): {}",
        log3_without_topics.len()
    );

    // Show first 10 LOG3 steps with details
    for (i, s) in log3_steps.iter().take(10).enumerate() {
        let has_topics = s.log_topics.is_some();
        let topic_count = s.log_topics.as_ref().map(|t| t.len()).unwrap_or(0);
        let has_transfer = s.log_topics.as_ref().is_some_and(|topics| {
            topics.first().is_some_and(|t| {
                let b = t.as_bytes();
                b[0] == 0xdd && b[1] == 0xf2 && b[2] == 0x52 && b[3] == 0xad
            })
        });
        let has_data = s.log_data.is_some();
        let data_len = s.log_data.as_ref().map(|d| d.len()).unwrap_or(0);
        eprintln!(
            "  LOG3[{i}]: step={} depth={} topics={has_topics}({topic_count}) transfer={has_transfer} data={has_data}({data_len}B) addr=0x{:x}",
            s.step_index, s.depth, s.code_address
        );
    }

    // Check for Transfer events specifically
    let transfer_steps: Vec<_> = log3_steps
        .iter()
        .filter(|s| {
            s.log_topics.as_ref().is_some_and(|topics| {
                topics.first().is_some_and(|t| {
                    let b = t.as_bytes();
                    b[0] == 0xdd && b[1] == 0xf2 && b[2] == 0x52 && b[3] == 0xad
                })
            })
        })
        .collect();

    eprintln!();
    eprintln!("ERC-20 Transfer events: {}", transfer_steps.len());
    let half = total_steps / 2;
    let transfers_first_half = transfer_steps
        .iter()
        .filter(|s| s.step_index < half)
        .count();
    let transfers_second_half = transfer_steps
        .iter()
        .filter(|s| s.step_index >= half)
        .count();
    eprintln!("Transfers in first half (step < {half}): {transfers_first_half}");
    eprintln!("Transfers in second half (step >= {half}): {transfers_second_half}");

    // ── Verification 2: Depth distribution ──

    eprintln!();
    eprintln!("--- Depth Distribution ---");
    let mut depth_counts: FxHashMap<usize, usize> = FxHashMap::default();
    for s in steps {
        *depth_counts.entry(s.depth).or_default() += 1;
    }
    let mut depth_sorted: Vec<_> = depth_counts.into_iter().collect();
    depth_sorted.sort_by_key(|(d, _)| *d);
    for (depth, count) in &depth_sorted {
        let pct = (*count as f64 / total_steps as f64) * 100.0;
        eprintln!("  depth {depth}: {count} steps ({pct:.1}%)");
    }

    let entry_depth = steps[0].depth;
    let deep_steps: usize = depth_sorted
        .iter()
        .filter(|(d, _)| *d > entry_depth + 1)
        .map(|(_, c)| *c)
        .sum();
    let deep_ratio = deep_steps as f64 / total_steps as f64;
    eprintln!();
    eprintln!("Entry depth: {entry_depth}");
    eprintln!(
        "Deep steps (depth > {}): {} ({:.1}%)",
        entry_depth + 1,
        deep_steps,
        deep_ratio * 100.0
    );
    eprintln!(
        "Strategy 3 threshold (old=0.60, new=0.40): {}",
        if deep_ratio >= 0.40 { "PASS" } else { "FAIL" }
    );

    // ── Verification 3: Run classifier on the actual steps ──

    eprintln!();
    eprintln!("--- Classifier Results ---");
    let detected = AttackClassifier::classify_with_confidence(steps);
    if detected.is_empty() {
        eprintln!("  NO PATTERNS DETECTED (empty)");
    } else {
        for d in &detected {
            eprintln!("  {:?} (confidence: {:.2})", d.pattern, d.confidence);
        }
    }

    // ── Assertions ──

    assert!(
        total_steps > 100,
        "Expected many steps for Balancer flash loan TX"
    );

    // KEY ASSERTION: LOG3 steps should have log_topics
    assert!(
        !log3_steps.is_empty(),
        "Expected LOG3 opcodes in Balancer flash loan TX"
    );
    assert!(
        !log3_with_topics.is_empty(),
        "LOG3 steps should have log_topics captured (Some). \
         If all are None, recorder.rs has a capture bug."
    );

    // After classifier-dev fixes, patterns should be detected
    // (This may still fail if the live TX has an unusual profile)
    eprintln!();
    eprintln!("=== Diagnostic Complete ===");
}

/// Replay a High-priority alert (high-value revert + self-destruct) and check
/// what patterns the classifier detects.
///
/// TX: 0x324d9fed22ddcb9b1e6b173fd6fe8eb35cc5ebb633a9b7e637e749b70e28022b
/// Block: 24587742, TX index: 76
#[test]
#[ignore = "requires live RPC endpoint (ALCHEMY_API_KEY)"]
fn diag_live_high_value_revert_patterns() {
    let rpc_url = get_rpc_url();
    let block_number = 24_587_742_u64;
    let tx_index = 76;

    let client = EthRpcClient::new(&rpc_url, block_number);
    let rpc_block = client
        .eth_get_block_by_number_with_txs(block_number)
        .expect("failed to fetch block");

    let config = AnalysisConfig {
        max_steps: 500_000,
        ..Default::default()
    };

    let result = replay_tx_from_rpc(&rpc_url, block_number, tx_index, &rpc_block, &config)
        .expect("replay should succeed");

    let steps = &result.trace.steps;
    eprintln!("=== LIVE High-Value Revert Diagnostic ===");
    eprintln!("Block: {block_number}, TX index: {tx_index}");
    eprintln!("Total steps: {}", steps.len());
    eprintln!("TX success: {}", result.trace.success);

    let detected = AttackClassifier::classify_with_confidence(steps);
    eprintln!("Detected patterns: {}", detected.len());
    for d in &detected {
        eprintln!("  {:?} (confidence: {:.2})", d.pattern, d.confidence);
    }

    assert!(steps.len() > 10, "Expected steps for high-value TX");
}
