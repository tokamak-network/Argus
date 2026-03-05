//! Sentinel Pipeline Latency Benchmark
//!
//! Measures per-stage latency of the Sentinel detection pipeline:
//!   - PreFilter::scan_tx (per-TX, expected: 10-50μs)
//!   - PreFilter::scan_block (per-block, various sizes)
//!
//! Usage:
//!   cargo run --example sentinel_latency_bench --features sentinel,autopsy
//!
//! Output: structured table with min/max/avg/p50/p95/p99 + JSON summary.

use std::time::{Duration, Instant};

use bytes::Bytes;
use ethrex_common::types::{
    BlockHeader, LegacyTransaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};

use argus::sentinel::pre_filter::PreFilter;
use argus::sentinel::types::SentinelConfig;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const WARMUP_ITERATIONS: usize = 100;
const BENCH_ITERATIONS: usize = 10_000;
const BLOCK_SIZES: &[usize] = &[10, 50, 100, 200, 500];

// ---------------------------------------------------------------------------
// Latency statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize)]
struct LatencyStats {
    name: String,
    iterations: usize,
    min_ns: u64,
    max_ns: u64,
    avg_ns: u64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    unit: String,
}

impl LatencyStats {
    fn from_durations(name: &str, durations: &mut [Duration], unit: &str) -> Self {
        assert!(
            !durations.is_empty(),
            "from_durations: empty input for '{name}'"
        );
        durations.sort();
        let len = durations.len();

        let nanos: Vec<u64> = durations.iter().map(|d| d.as_nanos() as u64).collect();

        let min_ns = nanos[0];
        let max_ns = nanos[len - 1];
        let sum: u64 = nanos.iter().sum();
        let avg_ns = sum / len as u64;
        let p50_ns = nanos[len * 50 / 100];
        let p95_ns = nanos[len * 95 / 100];
        let p99_ns = nanos[len * 99 / 100];

        Self {
            name: name.to_string(),
            iterations: len,
            min_ns,
            max_ns,
            avg_ns,
            p50_ns,
            p95_ns,
            p99_ns,
            unit: unit.to_string(),
        }
    }

    fn display_value(&self, ns: u64) -> String {
        match self.unit.as_str() {
            "us" => format!("{:.1}us", ns as f64 / 1_000.0),
            "ms" => format!("{:.2}ms", ns as f64 / 1_000_000.0),
            _ => format!("{}ns", ns),
        }
    }

    fn print_row(&self) {
        println!(
            "  {:<40} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
            self.name,
            self.display_value(self.min_ns),
            self.display_value(self.avg_ns),
            self.display_value(self.p50_ns),
            self.display_value(self.p95_ns),
            self.display_value(self.p99_ns),
            self.display_value(self.max_ns),
        );
    }
}

// ---------------------------------------------------------------------------
// TX fixture builders
// ---------------------------------------------------------------------------

fn random_address(seed: u8) -> Address {
    Address::from_slice(&[seed; 20])
}

fn one_eth() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

fn topic_with_prefix(prefix: [u8; 4]) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&prefix);
    H256::from(bytes)
}

fn transfer_topic() -> H256 {
    topic_with_prefix([0xdd, 0xf2, 0x52, 0xad])
}

fn make_log(address: Address, topics: Vec<H256>, data: Bytes) -> Log {
    Log {
        address,
        topics,
        data,
    }
}

fn make_receipt(succeeded: bool, cumulative_gas: u64, logs: Vec<Log>) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded,
        cumulative_gas_used: cumulative_gas,
        logs,
    }
}

fn make_tx_call(to: Address, value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Call(to),
        value,
        ..Default::default()
    })
}

fn make_erc20_transfer_log(from: Address, to: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..32].copy_from_slice(from.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..32].copy_from_slice(to.as_bytes());

    make_log(
        random_address(0xEE),
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]),
    )
}

fn aave_v2_pool() -> Address {
    let bytes = hex::decode("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9").unwrap();
    Address::from_slice(&bytes)
}

fn uniswap_v3_router() -> Address {
    let bytes = hex::decode("E592427A0AEce92De3Edee1F18E0157C05861564").unwrap();
    Address::from_slice(&bytes)
}

fn chainlink_eth_usd() -> Address {
    let bytes = hex::decode("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419").unwrap();
    Address::from_slice(&bytes)
}

// ---------------------------------------------------------------------------
// TX profiles (different complexity levels)
// ---------------------------------------------------------------------------

/// Simple ETH transfer: no logs, low gas. Expected: fastest path.
fn simple_transfer() -> (Transaction, Receipt) {
    let tx = make_tx_call(random_address(0x01), U256::from(1000), 21_000);
    let receipt = make_receipt(true, 21_000, vec![]);
    (tx, receipt)
}

/// DeFi swap: known contract, a few logs. Medium complexity.
fn defi_swap() -> (Transaction, Receipt) {
    let tx = make_tx_call(uniswap_v3_router(), U256::zero(), 300_000);
    let logs = vec![
        make_log(uniswap_v3_router(), vec![H256::zero()], Bytes::new()),
        make_erc20_transfer_log(random_address(0x10), random_address(0x11)),
        make_erc20_transfer_log(random_address(0x12), random_address(0x13)),
    ];
    let receipt = make_receipt(true, 250_000, logs);
    (tx, receipt)
}

/// Flash loan attack: flash loan topic + many ERC-20 transfers + oracle.
/// Highest complexity path through all heuristics.
fn flash_loan_attack() -> (Transaction, Receipt) {
    let aave_topic = topic_with_prefix([0x63, 0x10, 0x42, 0xc8]);
    let flash_log = make_log(aave_v2_pool(), vec![aave_topic], Bytes::new());

    let mut logs: Vec<Log> = (0..15)
        .map(|i| make_erc20_transfer_log(random_address(i), random_address(i + 100)))
        .collect();
    logs.insert(0, flash_log);

    // Add oracle + dex logs
    logs.push(make_log(
        chainlink_eth_usd(),
        vec![H256::zero()],
        Bytes::new(),
    ));
    logs.push(make_log(
        uniswap_v3_router(),
        vec![H256::zero()],
        Bytes::new(),
    ));

    let tx = make_tx_call(aave_v2_pool(), U256::zero(), 1_000_000);
    let receipt = make_receipt(true, 950_000, logs);
    (tx, receipt)
}

/// Reverted TX with high value: triggers H2 + H6 path.
fn high_value_revert() -> (Transaction, Receipt) {
    let tx = make_tx_call(random_address(0x01), one_eth() * 5, 3_000_000);
    let receipt = make_receipt(false, 2_000_000, vec![]);
    (tx, receipt)
}

/// Mixed block: 80% simple, 10% defi, 10% suspicious.
fn build_mixed_block(size: usize) -> (Vec<Transaction>, Vec<Receipt>) {
    let mut txs = Vec::with_capacity(size);
    let mut receipts = Vec::with_capacity(size);

    for i in 0..size {
        let (tx, receipt) = if i % 10 == 0 {
            flash_loan_attack()
        } else if i % 5 == 0 {
            defi_swap()
        } else {
            simple_transfer()
        };
        txs.push(tx);
        receipts.push(receipt);
    }

    (txs, receipts)
}

// ---------------------------------------------------------------------------
// Benchmark runner
// ---------------------------------------------------------------------------

fn bench_scan_tx(
    filter: &PreFilter,
    name: &str,
    tx: &Transaction,
    receipt: &Receipt,
    header: &BlockHeader,
) -> LatencyStats {
    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let _ = filter.scan_tx(tx, receipt, 0, header);
    }

    // Measure
    let mut durations = Vec::with_capacity(BENCH_ITERATIONS);
    for _ in 0..BENCH_ITERATIONS {
        let start = Instant::now();
        let _ = filter.scan_tx(tx, receipt, 0, header);
        durations.push(start.elapsed());
    }

    LatencyStats::from_durations(name, &mut durations, "us")
}

fn bench_scan_block(
    filter: &PreFilter,
    txs: &[Transaction],
    receipts: &[Receipt],
    header: &BlockHeader,
    iterations: usize,
) -> LatencyStats {
    let block_size = txs.len();

    // Warmup (fewer iterations for block-level)
    let warmup = (WARMUP_ITERATIONS / 10).max(10);
    for _ in 0..warmup {
        let _ = filter.scan_block(txs, receipts, header);
    }

    // Measure
    let mut durations = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = filter.scan_block(txs, receipts, header);
        durations.push(start.elapsed());
    }

    LatencyStats::from_durations(
        &format!("scan_block (n={})", block_size),
        &mut durations,
        if block_size >= 200 { "ms" } else { "us" },
    )
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    println!("==========================================================");
    println!("  Argus Sentinel — Latency Benchmark");
    println!("==========================================================");
    println!();
    println!("  Warmup:     {} iterations", WARMUP_ITERATIONS);
    println!("  Bench:      {} iterations (per-TX)", BENCH_ITERATIONS);
    println!("  Block sizes: {:?}", BLOCK_SIZES);
    println!();

    let filter = PreFilter::new(SentinelConfig::default());
    let header = BlockHeader {
        number: 19_500_000,
        ..Default::default()
    };

    // -----------------------------------------------------------------------
    // Part 1: Per-TX latency (scan_tx)
    // -----------------------------------------------------------------------
    println!("----------------------------------------------------------");
    println!("  Part 1: PreFilter::scan_tx (per-TX latency)");
    println!("----------------------------------------------------------");
    println!(
        "  {:<40} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Profile", "min", "avg", "p50", "p95", "p99", "max"
    );
    println!("  {}", "-".repeat(100));

    let mut all_stats: Vec<LatencyStats> = Vec::new();

    // Simple transfer
    let (tx, receipt) = simple_transfer();
    let stats = bench_scan_tx(&filter, "simple_transfer", &tx, &receipt, &header);
    stats.print_row();
    all_stats.push(stats);

    // DeFi swap
    let (tx, receipt) = defi_swap();
    let stats = bench_scan_tx(
        &filter,
        "defi_swap (known contract)",
        &tx,
        &receipt,
        &header,
    );
    stats.print_row();
    all_stats.push(stats);

    // Flash loan attack
    let (tx, receipt) = flash_loan_attack();
    let stats = bench_scan_tx(
        &filter,
        "flash_loan_attack (17 logs)",
        &tx,
        &receipt,
        &header,
    );
    stats.print_row();
    all_stats.push(stats);

    // High value revert
    let (tx, receipt) = high_value_revert();
    let stats = bench_scan_tx(&filter, "high_value_revert", &tx, &receipt, &header);
    stats.print_row();
    all_stats.push(stats);

    println!();

    // -----------------------------------------------------------------------
    // Part 2: Per-block latency (scan_block)
    // -----------------------------------------------------------------------
    println!("----------------------------------------------------------");
    println!("  Part 2: PreFilter::scan_block (per-block latency)");
    println!("----------------------------------------------------------");
    println!(
        "  {:<40} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "Block size", "min", "avg", "p50", "p95", "p99", "max"
    );
    println!("  {}", "-".repeat(100));

    for &size in BLOCK_SIZES {
        let (txs, receipts) = build_mixed_block(size);
        // Scale down iterations for larger blocks
        let iterations = (BENCH_ITERATIONS / size).max(100);
        let stats = bench_scan_block(&filter, &txs, &receipts, &header, iterations);
        stats.print_row();

        // Also compute per-tx throughput
        let avg_per_tx_us = stats.avg_ns as f64 / 1_000.0 / size as f64;
        let throughput_tx_per_sec = 1_000_000.0 / avg_per_tx_us;

        println!(
            "    -> {:.1}us/tx, {:.0} tx/sec throughput",
            avg_per_tx_us, throughput_tx_per_sec
        );

        all_stats.push(stats);
    }

    println!();

    // -----------------------------------------------------------------------
    // Part 3: Summary
    // -----------------------------------------------------------------------
    println!("----------------------------------------------------------");
    println!("  Summary");
    println!("----------------------------------------------------------");

    // Check if per-TX latency is within expected range (10-50us)
    let simple_p50_us = all_stats[0].p50_ns as f64 / 1_000.0;
    let flash_p50_us = all_stats[2].p50_ns as f64 / 1_000.0;

    println!("  Simple TX p50:      {:.1}us", simple_p50_us);
    println!("  Flash loan TX p50:  {:.1}us", flash_p50_us);

    if simple_p50_us <= 50.0 {
        println!("  [PASS] Simple TX within 50us target");
    } else {
        println!(
            "  [WARN] Simple TX exceeds 50us target ({:.1}us)",
            simple_p50_us
        );
    }

    if flash_p50_us <= 100.0 {
        println!("  [PASS] Flash loan TX within 100us target");
    } else {
        println!(
            "  [WARN] Flash loan TX exceeds 100us target ({:.1}us)",
            flash_p50_us
        );
    }

    println!();

    // -----------------------------------------------------------------------
    // Part 4: JSON output
    // -----------------------------------------------------------------------
    let json_output = serde_json::json!({
        "benchmark": "sentinel_latency",
        "config": {
            "warmup_iterations": WARMUP_ITERATIONS,
            "bench_iterations": BENCH_ITERATIONS,
            "block_sizes": BLOCK_SIZES,
        },
        "results": all_stats,
    });

    println!("----------------------------------------------------------");
    println!("  JSON Output");
    println!("----------------------------------------------------------");
    println!("{}", serde_json::to_string_pretty(&json_output).unwrap());
}
