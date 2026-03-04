//! Integration tests for autopsy CLI: arg parsing, formatter, and tx hash validation.

use bytes::Bytes;
use ethrex_common::Address;

use crate::types::{ReplayConfig, ReplayTrace, StepRecord};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_empty_trace() -> ReplayTrace {
    ReplayTrace {
        steps: vec![],
        config: ReplayConfig::default(),
        gas_used: 0,
        success: true,
        output: Bytes::new(),
    }
}

fn make_trace(steps: usize, gas_used: u64, success: bool) -> ReplayTrace {
    ReplayTrace {
        steps: (0..steps)
            .map(|i| StepRecord {
                step_index: i,
                pc: 0,
                opcode: 0x00,
                depth: 0,
                gas_remaining: 1_000_000,
                stack_top: vec![],
                stack_depth: 0,
                memory_size: 0,
                code_address: Address::default(),
                call_value: None,
                storage_writes: None,
                log_topics: None,
                log_data: None,
            })
            .collect(),
        config: ReplayConfig::default(),
        gas_used,
        success,
        output: Bytes::new(),
    }
}

// ─── Clap arg parsing ─────────────────────────────────────────────────────────

mod arg_parsing {
    use clap::Parser;

    use crate::cli::{Args, InputMode};

    #[test]
    fn test_autopsy_args_short_aliases() {
        // -t and -r short aliases should parse correctly
        let args = Args::try_parse_from([
            "argus",
            "autopsy",
            "-t",
            "0xabc123",
            "-r",
            "http://localhost:8545",
        ]);
        assert!(args.is_ok(), "short alias parse failed: {:?}", args.err());
        let args = args.unwrap();
        match args.command {
            InputMode::Autopsy {
                tx_hash, rpc_url, ..
            } => {
                assert_eq!(tx_hash, "0xabc123");
                assert_eq!(rpc_url, "http://localhost:8545");
            }
            _ => panic!("expected Autopsy subcommand"),
        }
    }

    #[test]
    fn test_autopsy_args_long_aliases() {
        // --tx and --rpc aliases should parse correctly
        let args = Args::try_parse_from([
            "argus",
            "autopsy",
            "--tx",
            "0xdeadbeef",
            "--rpc",
            "http://localhost:8545",
        ]);
        assert!(args.is_ok(), "long alias parse failed: {:?}", args.err());
        let args = args.unwrap();
        match args.command {
            InputMode::Autopsy {
                tx_hash, rpc_url, ..
            } => {
                assert_eq!(tx_hash, "0xdeadbeef");
                assert_eq!(rpc_url, "http://localhost:8545");
            }
            _ => panic!("expected Autopsy subcommand"),
        }
    }

    #[test]
    fn test_autopsy_args_canonical_long_flags() {
        // --tx-hash and --rpc-url (canonical names) should still work
        let args = Args::try_parse_from([
            "argus",
            "autopsy",
            "--tx-hash",
            "0x1234",
            "--rpc-url",
            "http://node.example.com",
        ]);
        assert!(
            args.is_ok(),
            "canonical long flag parse failed: {:?}",
            args.err()
        );
    }

    #[test]
    fn test_autopsy_interactive_short_flag() {
        // -i short flag for --interactive
        let args = Args::try_parse_from([
            "argus",
            "autopsy",
            "-t",
            "0xabc",
            "-r",
            "http://localhost:8545",
            "-i",
        ]);
        assert!(
            args.is_ok(),
            "interactive flag parse failed: {:?}",
            args.err()
        );
        let args = args.unwrap();
        match args.command {
            InputMode::Autopsy { interactive, .. } => {
                assert!(interactive);
            }
            _ => panic!("expected Autopsy subcommand"),
        }
    }

    #[test]
    fn test_autopsy_defaults() {
        // Defaults: format=markdown, rpc_timeout=30, rpc_retries=3, quiet=false, interactive=false
        let args = Args::try_parse_from([
            "argus",
            "autopsy",
            "-t",
            "0xabc",
            "-r",
            "http://localhost:8545",
        ])
        .expect("should parse");
        match args.command {
            InputMode::Autopsy {
                format,
                rpc_timeout,
                rpc_retries,
                quiet,
                interactive,
                ..
            } => {
                assert_eq!(format, "markdown");
                assert_eq!(rpc_timeout, 30);
                assert_eq!(rpc_retries, 3);
                assert!(!quiet);
                assert!(!interactive);
            }
            _ => panic!("expected Autopsy subcommand"),
        }
    }

    #[test]
    fn test_autopsy_missing_required_args_fails() {
        // Missing --rpc-url → parse error
        let result = Args::try_parse_from(["argus", "autopsy", "-t", "0xabc"]);
        assert!(result.is_err());
    }
}

// ─── format_autopsy_summary ──────────────────────────────────────────────────

mod fmt_summary {
    use ethrex_common::{Address, U256};

    use crate::autopsy::types::{AttackPattern, FundFlow};
    use crate::cli::formatter;

    use super::{make_empty_trace, make_trace};

    #[test]
    fn test_format_autopsy_summary_no_patterns() {
        let trace = make_empty_trace();
        let summary = formatter::format_autopsy_summary(&[], &[], &trace, "0xabcdef1234", 100);
        assert!(
            summary.contains("No attack patterns detected"),
            "expected 'No attack patterns detected' in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_no_flows() {
        let trace = make_empty_trace();
        let summary = formatter::format_autopsy_summary(&[], &[], &trace, "0xabcdef1234", 100);
        assert!(
            summary.contains("No fund flows detected"),
            "expected 'No fund flows detected' in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_risk_none_when_empty() {
        let trace = make_empty_trace();
        let summary = formatter::format_autopsy_summary(&[], &[], &trace, "0x1234", 1);
        assert!(
            summary.contains("Risk: NONE"),
            "expected Risk: NONE in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_with_reentrancy() {
        let trace = make_trace(10, 50_000, true);
        let patterns = vec![AttackPattern::Reentrancy {
            target_contract: Address::default(),
            reentrant_call_step: 2,
            state_modified_step: 5,
            call_depth_at_entry: 3,
        }];
        let summary =
            formatter::format_autopsy_summary(&patterns, &[], &trace, "0xaabbccdd1234", 999);
        assert!(
            summary.contains("Reentrancy"),
            "expected Reentrancy in:\n{summary}"
        );
        assert!(
            summary.contains("depth: 3"),
            "expected depth: 3 in:\n{summary}"
        );
        assert!(
            summary.contains("Risk: HIGH"),
            "expected Risk: HIGH in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_with_flash_loan() {
        let trace = make_trace(20, 100_000, true);
        let patterns = vec![AttackPattern::FlashLoan {
            borrow_step: 1,
            borrow_amount: U256::from(1_000_000u64),
            repay_step: 18,
            repay_amount: U256::from(1_000_900u64),
            provider: None,
            token: None,
        }];
        let summary = formatter::format_autopsy_summary(
            &patterns,
            &[],
            &trace,
            "0xffff000011112222",
            21_000_000,
        );
        assert!(
            summary.contains("FlashLoan"),
            "expected FlashLoan in:\n{summary}"
        );
        assert!(
            summary.contains("Risk: HIGH"),
            "expected Risk: HIGH in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_multiple_patterns_listed() {
        let trace = make_trace(50, 200_000, false);
        let patterns = vec![
            AttackPattern::Reentrancy {
                target_contract: Address::default(),
                reentrant_call_step: 10,
                state_modified_step: 20,
                call_depth_at_entry: 2,
            },
            AttackPattern::PriceManipulation {
                oracle_read_before: 5,
                swap_step: 15,
                oracle_read_after: 25,
                price_delta_percent: 42.0,
            },
        ];
        let summary =
            formatter::format_autopsy_summary(&patterns, &[], &trace, "0xdeadbeef12345678", 777);
        assert!(
            summary.contains("Attack Patterns: 2"),
            "missing pattern count in:\n{summary}"
        );
        assert!(
            summary.contains("Reentrancy"),
            "missing Reentrancy in:\n{summary}"
        );
        assert!(
            summary.contains("PriceManipulation"),
            "missing PriceManipulation in:\n{summary}"
        );
        assert!(
            summary.contains("Status: Reverted"),
            "missing reverted status in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_fund_flows() {
        let trace = make_trace(5, 21_000, true);
        let flows = vec![
            FundFlow {
                from: Address::default(),
                to: Address::default(),
                value: U256::from(1_000_000_000_000_000_000u64), // 1 ETH
                token: None,
                step_index: 1,
            },
            FundFlow {
                from: Address::default(),
                to: Address::default(),
                value: U256::from(500u64),
                token: Some(Address::default()),
                step_index: 2,
            },
        ];
        let summary =
            formatter::format_autopsy_summary(&[], &flows, &trace, "0xabc123def456", 55_000);
        assert!(
            summary.contains("Fund Flows: 2"),
            "missing flow count in:\n{summary}"
        );
        assert!(
            summary.contains("ETH:"),
            "missing ETH flow label in:\n{summary}"
        );
        assert!(
            summary.contains("ERC20:"),
            "missing ERC20 flow label in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_tx_hash_truncated() {
        let trace = make_empty_trace();
        let tx_hash = "0x46deef0fabcdef0012345678901234567890abcd7882";
        let summary = formatter::format_autopsy_summary(&[], &[], &trace, tx_hash, 1);
        // Should show first 10 chars + "..." + last 4 chars
        assert!(
            summary.contains("0x46deef0f"),
            "expected truncated prefix in:\n{summary}"
        );
        assert!(
            summary.contains("7882"),
            "expected truncated suffix in:\n{summary}"
        );
    }

    #[test]
    fn test_format_autopsy_summary_block_and_steps() {
        let trace = make_trace(145_302, 1_200_000, true);
        let summary = formatter::format_autopsy_summary(&[], &[], &trace, "0xtest1234", 21_989_247);
        assert!(
            summary.contains("21989247"),
            "missing block number in:\n{summary}"
        );
        assert!(
            summary.contains("145,302"),
            "missing formatted step count in:\n{summary}"
        );
        assert!(
            summary.contains("1,200,000"),
            "missing formatted gas in:\n{summary}"
        );
    }
}

// ─── TX hash validation (logic extracted from run_autopsy) ────────────────────

/// Parse a hex tx hash string (with optional 0x prefix) into 32 bytes.
/// Mirrors the validation logic in `run_autopsy`.
fn parse_tx_hash(tx_hash_hex: &str) -> Result<Vec<u8>, String> {
    let hash_hex = tx_hash_hex.strip_prefix("0x").unwrap_or(tx_hash_hex);
    if hash_hex.len() % 2 != 0 {
        return Err("tx hash hex must have even length".to_string());
    }
    let bytes: Result<Vec<u8>, _> = (0..hash_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hash_hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect();
    let bytes = bytes.map_err(|e| format!("invalid tx hash: {e}"))?;
    if bytes.len() != 32 {
        return Err("tx hash must be 32 bytes".to_string());
    }
    Ok(bytes)
}

#[test]
fn test_valid_tx_hash_32_bytes() {
    let hash = "0x".to_string() + &"ab".repeat(32);
    assert!(parse_tx_hash(&hash).is_ok());
}

#[test]
fn test_valid_tx_hash_without_0x_prefix() {
    let hash = "ab".repeat(32);
    assert!(parse_tx_hash(&hash).is_ok());
}

#[test]
fn test_invalid_tx_hash_odd_length() {
    let result = parse_tx_hash("0xabc"); // 3 hex chars = odd
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("even length"));
}

#[test]
fn test_invalid_tx_hash_too_short() {
    let hash = "0x".to_string() + &"ab".repeat(10); // 10 bytes, not 32
    let result = parse_tx_hash(&hash);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("32 bytes"));
}

#[test]
fn test_invalid_tx_hash_too_long() {
    let hash = "0x".to_string() + &"ab".repeat(33); // 33 bytes
    let result = parse_tx_hash(&hash);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("32 bytes"));
}

#[test]
fn test_invalid_tx_hash_non_hex_chars() {
    let hash = "0x".to_string() + &"zz".repeat(32);
    let result = parse_tx_hash(&hash);
    assert!(result.is_err());
}
