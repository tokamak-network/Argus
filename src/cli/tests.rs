//! CLI argument parsing tests for sentinel subcommand.

use super::{Args, InputMode};
use clap::Parser;
use std::path::PathBuf;

#[test]
fn test_sentinel_args_basic() {
    let args = Args::try_parse_from(["argus", "sentinel", "--rpc", "http://localhost:8545"])
        .expect("basic sentinel args should parse");
    let InputMode::Sentinel {
        rpc_url,
        prefilter_only,
        metrics_port,
        poll_interval,
        alert_file,
        webhook_url,
        ..
    } = args.command
    else {
        panic!("expected Sentinel variant");
    };
    assert_eq!(rpc_url, "http://localhost:8545");
    assert!(!prefilter_only);
    assert_eq!(metrics_port, 9090);
    assert_eq!(poll_interval, 2);
    assert!(alert_file.is_none());
    assert!(webhook_url.is_none());
}

#[test]
fn test_sentinel_args_defaults() {
    let args = Args::try_parse_from([
        "argus",
        "sentinel",
        "--rpc-url",
        "https://mainnet.infura.io",
    ])
    .expect("sentinel args with --rpc-url alias should parse");
    let InputMode::Sentinel {
        rpc_url,
        prefilter_only,
        metrics_port,
        poll_interval,
        ..
    } = args.command
    else {
        panic!("expected Sentinel variant");
    };
    assert_eq!(rpc_url, "https://mainnet.infura.io");
    assert!(!prefilter_only);
    assert_eq!(metrics_port, 9090);
    assert_eq!(poll_interval, 2);
}

#[test]
fn test_sentinel_args_all_options() {
    let args = Args::try_parse_from([
        "argus",
        "sentinel",
        "--rpc",
        "https://eth.example.com",
        "--alert-file",
        "/tmp/alerts.jsonl",
        "--prefilter-only",
        "--metrics-port",
        "9100",
        "--webhook-url",
        "https://hooks.slack.com/services/XXX",
        "--poll-interval",
        "5",
    ])
    .expect("sentinel args with all options should parse");
    let InputMode::Sentinel {
        rpc_url,
        alert_file,
        prefilter_only,
        metrics_port,
        webhook_url,
        poll_interval,
        ..
    } = args.command
    else {
        panic!("expected Sentinel variant");
    };
    assert_eq!(rpc_url, "https://eth.example.com");
    assert_eq!(alert_file, Some(PathBuf::from("/tmp/alerts.jsonl")));
    assert!(prefilter_only);
    assert_eq!(metrics_port, 9100);
    assert_eq!(
        webhook_url.as_deref(),
        Some("https://hooks.slack.com/services/XXX")
    );
    assert_eq!(poll_interval, 5);
}

// ---------------------------------------------------------------------------
// parse_tx_hash tests
// ---------------------------------------------------------------------------

#[test]
fn test_parse_tx_hash_with_0x_prefix() {
    let hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let result = super::parse_tx_hash(hash);
    assert!(result.is_ok());
    let h = result.unwrap();
    assert_eq!(h.as_bytes()[0], 0xab);
    assert_eq!(h.as_bytes()[31], 0x90);
}

#[test]
fn test_parse_tx_hash_without_prefix() {
    let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let result = super::parse_tx_hash(hash);
    assert!(result.is_ok());
}

#[test]
fn test_parse_tx_hash_odd_length() {
    let hash = "0xabc"; // 3 hex chars (odd)
    let result = super::parse_tx_hash(hash);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("even length"), "error: {err}");
}

#[test]
fn test_parse_tx_hash_invalid_hex() {
    let hash = "0xGGGGGG1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let result = super::parse_tx_hash(hash);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("invalid tx hash"), "error: {err}");
}

#[test]
fn test_parse_tx_hash_wrong_length() {
    let hash = "0xabcdef"; // only 3 bytes, not 32
    let result = super::parse_tx_hash(hash);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("32 bytes"), "error: {err}");
}
