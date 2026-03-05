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
