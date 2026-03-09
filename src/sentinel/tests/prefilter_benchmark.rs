//! Pre-filter benchmark — confusion matrix evaluation.
//!
//! Tests the pre-filter against curated scenarios with known ground truth
//! (attack vs normal) and produces precision/recall/F1 metrics.
//!
//! Run: `cargo test prefilter_benchmark -- --nocapture`

use bytes::Bytes;
use ethrex_common::types::Log;
use ethrex_common::{Address, H256, U256};

use super::*;
use crate::sentinel::pre_filter::PreFilter;
use crate::sentinel::types::SentinelConfig;
use crate::sentinel::whitelist::WhitelistEngine;

// ---------------------------------------------------------------------------
// Benchmark fixture definition
// ---------------------------------------------------------------------------

struct BenchmarkCase {
    name: &'static str,
    is_attack: bool,
    tx: Transaction,
    receipt: Receipt,
    /// Which heuristics SHOULD fire for this case (for diagnostic output)
    #[allow(dead_code)]
    expected_signals: &'static str,
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

fn addr(hex: &str) -> Address {
    let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).expect("valid hex");
    Address::from_slice(&bytes)
}

fn balancer_vault() -> Address {
    addr("BA12222222228d8Ba445958a75a0704d566BF2C8")
}
fn aave_v2() -> Address {
    addr("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9")
}
fn aave_v3() -> Address {
    addr("87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
}
fn uniswap_v2_router() -> Address {
    addr("7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
}
fn uniswap_v3_router_addr() -> Address {
    addr("E592427A0AEce92De3Edee1F18E0157C05861564")
}
fn chainlink_eth_usd_addr() -> Address {
    addr("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419")
}
fn oneinch_v5() -> Address {
    addr("1111111254EEB25477B68fb85Ed929f73A960582")
}
fn sushiswap() -> Address {
    addr("d9e1cE17f2641f24aE83637AB66a2cca9C378532")
}
fn unknown_addr(seed: u8) -> Address {
    Address::from_slice(&[seed; 20])
}
fn one_eth() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

// ---------------------------------------------------------------------------
// Log/topic builders
// ---------------------------------------------------------------------------

fn flash_topic_aave() -> H256 {
    topic_with_prefix([0x63, 0x10, 0x42, 0xc8])
}
fn flash_topic_balancer() -> H256 {
    topic_with_prefix([0x0d, 0x7d, 0x75, 0xe0])
}
fn flash_topic_uniswap() -> H256 {
    topic_with_prefix([0xbd, 0xbd, 0xb7, 0x16])
}

/// Pool address used as the "source" in normal symmetric DeFi flows.
fn pool_addr() -> Address {
    unknown_addr(0xAB)
}

/// User address used as the "destination" in normal symmetric DeFi flows.
fn user_addr() -> Address {
    unknown_addr(0xCD)
}

/// ERC-20 Transfer log with realistic from/to for symmetric patterns.
/// First-half transfers: pool → user (borrow phase).
fn erc20_borrow_log(emitter: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(pool_addr().as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(user_addr().as_bytes());
    make_log(
        emitter,
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]),
    )
}

/// ERC-20 Transfer log with realistic from/to for symmetric patterns.
/// Second-half transfers: user → pool (repay phase).
fn erc20_repay_log(emitter: Address, pool: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(user_addr().as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(pool.as_bytes());
    make_log(
        emitter,
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]),
    )
}

/// ERC-20 transfer log for non-flash-loan normal scenarios (simple swap).
/// Uses unique from/to per call to avoid zero-address masking.
fn erc20_transfer_log(emitter: Address) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[12..].copy_from_slice(emitter.as_bytes());
    let mut to_bytes = [0u8; 32];
    to_bytes[12..].copy_from_slice(user_addr().as_bytes());
    make_log(
        emitter,
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]),
    )
}

/// ERC-20 transfer log with DISTINCT from/to addresses (asymmetric pattern).
/// Used for attack scenarios where funds flow to new/unknown destinations.
fn erc20_drain_log(emitter: Address, from_seed: u8, to_seed: u8) -> Log {
    let mut from_bytes = [0u8; 32];
    from_bytes[31] = from_seed;
    let mut to_bytes = [0u8; 32];
    to_bytes[31] = to_seed;
    make_log(
        emitter,
        vec![
            transfer_topic(),
            H256::from(from_bytes),
            H256::from(to_bytes),
        ],
        Bytes::from(vec![0u8; 32]),
    )
}

fn flash_log(provider: Address, topic: H256) -> Log {
    make_log(provider, vec![topic], Bytes::new())
}

// ---------------------------------------------------------------------------
// Attack scenarios — SHOULD be detected (True Positive)
// ---------------------------------------------------------------------------

fn attack_flash_loan_reentrancy() -> BenchmarkCase {
    // Modeled after: DAO hack, Cream Finance, Rari Fuse
    // Attack targets UNKNOWN contract, funds drain to attacker (asymmetric).
    let mut logs = vec![flash_log(unknown_addr(0xF0), flash_topic_aave())];
    for i in 0..12u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 50), i, i + 200));
    }
    BenchmarkCase {
        name: "flash_loan_reentrancy (DAO/Cream style)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xAA), U256::zero(), 3_000_000),
        receipt: make_receipt(false, 2_500_000, logs),
        expected_signals: "H1(flash) + H2(revert+erc20) + H3(12 transfers) + H5(gas) + H8(asymmetric)",
    }
}

fn attack_flash_loan_price_manipulation() -> BenchmarkCase {
    // Modeled after: Harvest Finance, Warp Finance, Value DeFi
    // Known contracts in logs (Chainlink, Uniswap) -> relevance gate applies.
    let mut logs = vec![
        flash_log(unknown_addr(0xF1), flash_topic_balancer()),
        make_log(chainlink_eth_usd_addr(), vec![H256::zero()], Bytes::new()),
        make_log(uniswap_v3_router_addr(), vec![H256::zero()], Bytes::new()),
    ];
    for i in 0..15u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 60), i, i + 200));
    }
    BenchmarkCase {
        name: "flash_loan_price_manipulation (Harvest style)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xBB), U256::zero(), 5_000_000),
        receipt: make_receipt(true, 4_800_000, logs),
        expected_signals: "H1(flash) + H3(15 transfers) + H4(known) + H5(gas) + H7(oracle+dex) + H8(asymmetric)",
    }
}

fn attack_flash_loan_direct_theft() -> BenchmarkCase {
    // Modeled after: Euler Finance ($197M), bZx
    // Attack from unknown contract (no relevance gate).
    let mut logs = vec![flash_log(unknown_addr(0xF2), flash_topic_aave())];
    for i in 0..25u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 70), i, i + 200));
    }
    BenchmarkCase {
        name: "flash_loan_direct_theft (Euler style)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xCC), one_eth() * 100, 8_000_000),
        receipt: make_receipt(false, 7_500_000, logs),
        expected_signals: "H1(flash) + H2(high value revert) + H3(25 transfers) + H5(gas) + H8(asymmetric)",
    }
}

fn attack_self_destruct_drain() -> BenchmarkCase {
    // Modeled after: Parity wallet hack
    BenchmarkCase {
        name: "self_destruct_drain (Parity style)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xDD), one_eth() * 10, 3_000_000),
        receipt: make_receipt(false, 2_000_000, vec![]),
        expected_signals: "H2(high value revert) + H6(self-destruct)",
    }
}

fn attack_oracle_manipulation_no_flash_loan() -> BenchmarkCase {
    // Modeled after: Mango Markets
    // Known contracts in logs -> relevance gate applies but multiple strong signals.
    let mut logs = vec![
        make_log(chainlink_eth_usd_addr(), vec![H256::zero()], Bytes::new()),
        make_log(uniswap_v3_router_addr(), vec![H256::zero()], Bytes::new()),
    ];
    for i in 0..8u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 80), i, i + 200));
    }
    BenchmarkCase {
        name: "oracle_manipulation_no_flash_loan (Mango style)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xEE), U256::zero(), 2_000_000),
        receipt: make_receipt(true, 1_900_000, logs),
        expected_signals: "H3(8 transfers) + H4(known) + H5(gas) + H7(oracle+dex)",
    }
}

fn attack_failed_exploit_attempt() -> BenchmarkCase {
    // High gas burned, high value, revert
    BenchmarkCase {
        name: "failed_exploit_attempt (high value revert)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xFF), one_eth() * 50, 5_000_000),
        receipt: make_receipt(false, 4_500_000, vec![]),
        expected_signals: "H2(high value revert) + H5(gas) + H6(self-destruct)",
    }
}

fn attack_uniswap_v3_flash_exploit() -> BenchmarkCase {
    // Uniswap V3 flash + drain unknown protocol (no known contract in tx.to)
    let mut logs = vec![flash_log(unknown_addr(0x33), flash_topic_uniswap())];
    for i in 0..20u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 90), i, i + 200));
    }
    BenchmarkCase {
        name: "uniswap_v3_flash_exploit",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0x44), U256::zero(), 6_000_000),
        receipt: make_receipt(true, 5_800_000, logs),
        expected_signals: "H1(flash) + H3(20 transfers) + H5(gas) + H8(asymmetric)",
    }
}

fn attack_flash_loan_asymmetric_drain() -> BenchmarkCase {
    // Flash loan with clear asymmetric cash flow: borrowed funds drained to unknown addr.
    let mut logs = vec![flash_log(unknown_addr(0xA0), flash_topic_aave())];
    // First half: pool -> attacker (borrow)
    for i in 0..5u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 0xB0), 0xA0, 0xA1));
    }
    // Second half: attacker -> drain (NOT back to pool)
    for i in 0..5u8 {
        logs.push(erc20_drain_log(unknown_addr(i + 0xC0), 0xA1, 0xA2));
    }

    BenchmarkCase {
        name: "flash_loan_asymmetric_drain (new)",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xA1), U256::zero(), 2_000_000),
        receipt: make_receipt(true, 1_900_000, logs),
        expected_signals: "H1(flash) + H3(10 transfers) + H5(gas) + H8(asymmetric)",
    }
}

// ---------------------------------------------------------------------------
// Normal DeFi scenarios — should NOT be detected (True Negative)
// ---------------------------------------------------------------------------

fn normal_balancer_arbitrage() -> BenchmarkCase {
    // THE FALSE POSITIVE causing Alchemy cost explosion
    // Symmetric transfers: first half borrow from Balancer, second half repay to Balancer.
    let mut logs = vec![flash_log(balancer_vault(), flash_topic_balancer())];
    // First half: borrow phase (pool → user)
    for i in 0..11u8 {
        logs.push(erc20_borrow_log(unknown_addr(i + 10)));
    }
    // Second half: repay phase (user → Balancer Vault = flash provider)
    for i in 0..11u8 {
        logs.push(erc20_repay_log(unknown_addr(i + 10), balancer_vault()));
    }

    BenchmarkCase {
        name: "balancer_arbitrage_bot [KNOWN FP]",
        is_attack: false,
        tx: make_tx_call(balancer_vault(), U256::zero(), 2_000_000),
        receipt: make_receipt(true, 1_900_000, logs),
        expected_signals: "none (normal DeFi arb)",
    }
}

fn normal_aave_flash_loan_arbitrage() -> BenchmarkCase {
    // Aave flash loan -> swap on DEXes -> repay with profit (symmetric)
    let mut logs = vec![
        flash_log(aave_v3(), flash_topic_aave()),
        make_log(uniswap_v3_router_addr(), vec![H256::zero()], Bytes::new()),
    ];
    // First half: borrow phase
    for i in 0..9u8 {
        logs.push(erc20_borrow_log(unknown_addr(i + 30)));
    }
    // Second half: repay phase (funds return to Aave V3 = flash provider)
    for i in 0..9u8 {
        logs.push(erc20_repay_log(unknown_addr(i + 30), aave_v3()));
    }
    BenchmarkCase {
        name: "aave_flash_loan_arbitrage [KNOWN FP]",
        is_attack: false,
        tx: make_tx_call(unknown_addr(0x11), U256::zero(), 1_500_000),
        receipt: make_receipt(true, 1_400_000, logs),
        expected_signals: "none (normal flash arb)",
    }
}

fn normal_aave_liquidation() -> BenchmarkCase {
    let mut logs = vec![];
    for i in 0..6u8 {
        logs.push(erc20_transfer_log(unknown_addr(i + 40)));
    }
    logs.push(make_log(aave_v3(), vec![H256::zero()], Bytes::new()));
    BenchmarkCase {
        name: "aave_liquidation",
        is_attack: false,
        tx: make_tx_call(aave_v3(), U256::zero(), 500_000),
        receipt: make_receipt(true, 350_000, logs),
        expected_signals: "none (normal liquidation)",
    }
}

fn normal_uniswap_single_swap() -> BenchmarkCase {
    let logs = vec![
        erc20_transfer_log(unknown_addr(0x01)),
        erc20_transfer_log(unknown_addr(0x02)),
    ];
    BenchmarkCase {
        name: "uniswap_single_swap",
        is_attack: false,
        tx: make_tx_call(uniswap_v2_router(), U256::zero(), 200_000),
        receipt: make_receipt(true, 150_000, logs),
        expected_signals: "none (normal swap)",
    }
}

fn normal_multi_hop_swap() -> BenchmarkCase {
    let mut logs = vec![make_log(
        uniswap_v3_router_addr(),
        vec![H256::zero()],
        Bytes::new(),
    )];
    for i in 0..6u8 {
        logs.push(erc20_transfer_log(unknown_addr(i + 20)));
    }
    BenchmarkCase {
        name: "multi_hop_swap (6 transfers)",
        is_attack: false,
        tx: make_tx_call(uniswap_v3_router_addr(), U256::zero(), 400_000),
        receipt: make_receipt(true, 350_000, logs),
        expected_signals: "none (normal multi-hop)",
    }
}

fn normal_1inch_aggregator_swap() -> BenchmarkCase {
    let mut logs = vec![];
    for i in 0..12u8 {
        logs.push(erc20_transfer_log(unknown_addr(i + 40)));
    }
    logs.push(make_log(oneinch_v5(), vec![H256::zero()], Bytes::new()));
    BenchmarkCase {
        name: "1inch_aggregator_swap (12 transfers)",
        is_attack: false,
        tx: make_tx_call(oneinch_v5(), U256::zero(), 600_000),
        receipt: make_receipt(true, 500_000, logs),
        expected_signals: "none (normal aggregator swap)",
    }
}

fn normal_sushiswap_swap() -> BenchmarkCase {
    let logs = vec![
        erc20_transfer_log(unknown_addr(0x05)),
        erc20_transfer_log(unknown_addr(0x06)),
        erc20_transfer_log(unknown_addr(0x07)),
    ];
    BenchmarkCase {
        name: "sushiswap_swap",
        is_attack: false,
        tx: make_tx_call(sushiswap(), U256::zero(), 250_000),
        receipt: make_receipt(true, 180_000, logs),
        expected_signals: "none (normal swap)",
    }
}

fn normal_eth_transfer() -> BenchmarkCase {
    BenchmarkCase {
        name: "simple_eth_transfer",
        is_attack: false,
        tx: make_tx_call(unknown_addr(0x01), one_eth() * 5, 21_000),
        receipt: make_receipt(true, 21_000, vec![]),
        expected_signals: "none",
    }
}

fn normal_contract_deploy() -> BenchmarkCase {
    BenchmarkCase {
        name: "contract_deployment",
        is_attack: false,
        tx: make_tx_call(unknown_addr(0x01), U256::zero(), 2_000_000),
        receipt: make_receipt(true, 1_500_000, vec![]),
        expected_signals: "none",
    }
}

fn normal_large_eth_transfer_success() -> BenchmarkCase {
    BenchmarkCase {
        name: "large_eth_transfer_success (100 ETH)",
        is_attack: false,
        tx: make_tx_call(unknown_addr(0x02), one_eth() * 100, 21_000),
        receipt: make_receipt(true, 21_000, vec![]),
        expected_signals: "none (success, no revert)",
    }
}

fn normal_failed_swap_low_value() -> BenchmarkCase {
    BenchmarkCase {
        name: "failed_swap_low_value",
        is_attack: false,
        tx: make_tx_call(uniswap_v2_router(), U256::from(1000), 200_000),
        receipt: make_receipt(false, 50_000, vec![]),
        expected_signals: "none (low value revert)",
    }
}

fn normal_chainlink_price_feed_read() -> BenchmarkCase {
    let logs = vec![make_log(
        chainlink_eth_usd_addr(),
        vec![H256::zero()],
        Bytes::new(),
    )];
    BenchmarkCase {
        name: "chainlink_price_read_only",
        is_attack: false,
        tx: make_tx_call(unknown_addr(0x03), U256::zero(), 100_000),
        receipt: make_receipt(true, 50_000, logs),
        expected_signals: "none (oracle read without DEX)",
    }
}

fn normal_uniswap_flash_loan_arb() -> BenchmarkCase {
    // Symmetric transfers: funds return to flash provider
    let provider = unknown_addr(0x55);
    let mut logs = vec![flash_log(provider, flash_topic_uniswap())];
    // First half: borrow phase
    for i in 0..7u8 {
        logs.push(erc20_borrow_log(unknown_addr(i + 50)));
    }
    // Second half: repay phase (funds return to provider)
    for i in 0..8u8 {
        logs.push(erc20_repay_log(unknown_addr(i + 50), provider));
    }
    BenchmarkCase {
        name: "uniswap_v3_flash_arb [KNOWN FP]",
        is_attack: false,
        tx: make_tx_call(provider, U256::zero(), 1_000_000),
        receipt: make_receipt(true, 950_000, logs),
        expected_signals: "none (normal flash arb)",
    }
}

fn normal_balancer_arb_high_transfers() -> BenchmarkCase {
    // Balancer flash loan arb with 30+ ERC-20 transfers. Should be TN.
    let mut logs = vec![flash_log(balancer_vault(), flash_topic_balancer())];
    // First half: borrow phase
    for i in 0..17u8 {
        logs.push(erc20_borrow_log(unknown_addr(i + 10)));
    }
    // Second half: repay to Balancer Vault
    for i in 0..18u8 {
        logs.push(erc20_repay_log(unknown_addr(i + 10), balancer_vault()));
    }

    BenchmarkCase {
        name: "balancer_arb_high_transfers (30+ ERC20, new)",
        is_attack: false,
        tx: make_tx_call(balancer_vault(), U256::zero(), 3_000_000),
        receipt: make_receipt(true, 2_800_000, logs),
        expected_signals: "none (normal high-volume arb)",
    }
}

// ---------------------------------------------------------------------------
// Edge cases — attacks the filter MISSES (False Negative risk)
// ---------------------------------------------------------------------------

fn edge_governance_attack() -> BenchmarkCase {
    let logs = vec![
        erc20_transfer_log(unknown_addr(0xA1)),
        erc20_transfer_log(unknown_addr(0xA2)),
    ];
    BenchmarkCase {
        name: "governance_attack (Beanstalk style) [EXPECTED FN]",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xAA), U256::zero(), 300_000),
        receipt: make_receipt(true, 250_000, logs),
        expected_signals: "NONE — invisible to current heuristics",
    }
}

fn edge_access_control_bypass() -> BenchmarkCase {
    BenchmarkCase {
        name: "access_control_bypass (Poly Network style) [EXPECTED FN]",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xBB), U256::zero(), 100_000),
        receipt: make_receipt(true, 60_000, vec![erc20_transfer_log(unknown_addr(0xB1))]),
        expected_signals: "NONE — looks like normal admin call",
    }
}

fn edge_logic_bug_single_transfer() -> BenchmarkCase {
    let logs = vec![
        erc20_transfer_log(unknown_addr(0xC1)),
        erc20_transfer_log(unknown_addr(0xC2)),
        erc20_transfer_log(unknown_addr(0xC3)),
    ];
    BenchmarkCase {
        name: "logic_bug_mint_exploit (Wormhole style) [EXPECTED FN]",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xCC), U256::zero(), 200_000),
        receipt: make_receipt(true, 150_000, logs),
        expected_signals: "NONE — normal-looking token transfers",
    }
}

fn edge_reentrancy_low_gas() -> BenchmarkCase {
    let mut logs = vec![flash_log(unknown_addr(0xD0), flash_topic_aave())];
    for i in 0..4u8 {
        logs.push(erc20_transfer_log(unknown_addr(i + 0xD0)));
    }
    BenchmarkCase {
        name: "reentrancy_low_gas [EXPECTED FN]",
        is_attack: true,
        tx: make_tx_call(unknown_addr(0xDD), U256::zero(), 400_000),
        receipt: make_receipt(true, 350_000, logs),
        expected_signals: "NONE — below ERC20 threshold, low gas",
    }
}

fn edge_sandwich_attack() -> BenchmarkCase {
    let logs = vec![
        erc20_transfer_log(unknown_addr(0xE1)),
        erc20_transfer_log(unknown_addr(0xE2)),
        make_log(uniswap_v2_router(), vec![H256::zero()], Bytes::new()),
    ];
    BenchmarkCase {
        name: "sandwich_attack_single_leg [EXPECTED FN]",
        is_attack: true,
        tx: make_tx_call(uniswap_v2_router(), U256::zero(), 200_000),
        receipt: make_receipt(true, 150_000, logs),
        expected_signals: "NONE — looks like normal swap (need multi-TX context)",
    }
}

// ---------------------------------------------------------------------------
// Confusion matrix evaluation
// ---------------------------------------------------------------------------

struct ConfusionMatrix {
    tp: Vec<&'static str>,
    fp: Vec<&'static str>,
    tn: Vec<&'static str>,
    fn_: Vec<&'static str>,
}

impl ConfusionMatrix {
    fn precision(&self) -> f64 {
        let tp = self.tp.len() as f64;
        let fp = self.fp.len() as f64;
        if tp + fp == 0.0 { 0.0 } else { tp / (tp + fp) }
    }

    fn recall(&self) -> f64 {
        let tp = self.tp.len() as f64;
        let fn_ = self.fn_.len() as f64;
        if tp + fn_ == 0.0 {
            0.0
        } else {
            tp / (tp + fn_)
        }
    }

    fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

fn run_benchmark(filter: &PreFilter, cases: &[BenchmarkCase]) -> ConfusionMatrix {
    let header = make_header(20_000_000);
    let mut matrix = ConfusionMatrix {
        tp: vec![],
        fp: vec![],
        tn: vec![],
        fn_: vec![],
    };

    for case in cases {
        let result = filter.scan_tx(&case.tx, &case.receipt, 0, &header);
        let detected = result.is_some();

        match (case.is_attack, detected) {
            (true, true) => matrix.tp.push(case.name),
            (true, false) => matrix.fn_.push(case.name),
            (false, true) => matrix.fp.push(case.name),
            (false, false) => matrix.tn.push(case.name),
        }
    }

    matrix
}

fn all_cases() -> Vec<BenchmarkCase> {
    vec![
        // Attacks (8, including new case)
        attack_flash_loan_reentrancy(),
        attack_flash_loan_price_manipulation(),
        attack_flash_loan_direct_theft(),
        attack_self_destruct_drain(),
        attack_oracle_manipulation_no_flash_loan(),
        attack_failed_exploit_attempt(),
        attack_uniswap_v3_flash_exploit(),
        attack_flash_loan_asymmetric_drain(),
        // Edge case attacks — expected FN (5)
        edge_governance_attack(),
        edge_access_control_bypass(),
        edge_logic_bug_single_transfer(),
        edge_reentrancy_low_gas(),
        edge_sandwich_attack(),
        // Normal DeFi (14, including new case)
        normal_balancer_arbitrage(),
        normal_aave_flash_loan_arbitrage(),
        normal_aave_liquidation(),
        normal_uniswap_single_swap(),
        normal_multi_hop_swap(),
        normal_1inch_aggregator_swap(),
        normal_sushiswap_swap(),
        normal_eth_transfer(),
        normal_contract_deploy(),
        normal_large_eth_transfer_success(),
        normal_failed_swap_low_value(),
        normal_chainlink_price_feed_read(),
        normal_uniswap_flash_loan_arb(),
        normal_balancer_arb_high_transfers(),
    ]
}

fn print_matrix(label: &str, m: &ConfusionMatrix) {
    println!("\n=== {label} ===");
    println!(
        "  TP ({:2}): {}",
        m.tp.len(),
        if m.tp.is_empty() { "(none)" } else { "" }
    );
    for name in &m.tp {
        println!("          + {name}");
    }
    println!(
        "  FP ({:2}): {}",
        m.fp.len(),
        if m.fp.is_empty() { "(none)" } else { "" }
    );
    for name in &m.fp {
        println!("          ! {name}");
    }
    println!(
        "  TN ({:2}): {}",
        m.tn.len(),
        if m.tn.is_empty() { "(none)" } else { "" }
    );
    for name in &m.tn {
        println!("          - {name}");
    }
    println!(
        "  FN ({:2}): {}",
        m.fn_.len(),
        if m.fn_.is_empty() { "(none)" } else { "" }
    );
    for name in &m.fn_ {
        println!("          X {name}");
    }
    println!();
    println!("  Precision: {:.1}%", m.precision() * 100.0);
    println!("  Recall:    {:.1}%", m.recall() * 100.0);
    println!("  F1 Score:  {:.1}%", m.f1() * 100.0);
    println!(
        "  Total: {} cases ({} attacks, {} normal)",
        m.tp.len() + m.fp.len() + m.tn.len() + m.fn_.len(),
        m.tp.len() + m.fn_.len(),
        m.tn.len() + m.fp.len()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Benchmark with current production config (threshold=0.7, no whitelist).
#[test]
fn prefilter_benchmark_production_config() {
    let config = SentinelConfig {
        suspicion_threshold: 0.7,
        min_value_wei: one_eth(),
        min_gas_used: 500_000,
        min_erc20_transfers: 5,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
        mev_flash_loan_factor: 1.0,
        mev_selfdestruct_factor: 1.0,
    };
    let filter = PreFilter::new(config);
    let cases = all_cases();
    let m = run_benchmark(&filter, &cases);

    print_matrix("Production Config (threshold=0.7, no whitelist)", &m);

    // All 3 known FP cases should now be TN (no false positives)
    assert_eq!(
        m.fp.len(),
        0,
        "Expected 0 FP after scoring improvements, got: {:?}",
        m.fp
    );

    // Edge case attacks are expected FN
    assert!(m.fn_.len() >= 5, "Expect at least 5 FN (edge cases)");

    // Production config (threshold=0.7) is stricter; expect fewer TP than default
    assert!(
        m.tp.len() >= 3,
        "Expect at least 3 TP from core attack cases with production config, got {}",
        m.tp.len()
    );

    // Precision should be 100% (no FP)
    if !m.tp.is_empty() {
        assert!(
            (m.precision() - 1.0).abs() < f64::EPSILON,
            "Precision should be 100% with 0 FP"
        );
    }
}

/// Benchmark with default config (threshold=0.5, no whitelist).
#[test]
fn prefilter_benchmark_default_config() {
    let filter = PreFilter::default();
    let cases = all_cases();
    let m = run_benchmark(&filter, &cases);

    print_matrix("Default Config (threshold=0.5, no whitelist)", &m);

    // No FP expected
    assert_eq!(m.fp.len(), 0, "Expected 0 FP, got: {:?}", m.fp);
}

/// Benchmark with whitelist enabled.
#[test]
fn prefilter_benchmark_with_whitelist() {
    use crate::sentinel::whitelist::{WhitelistCategory, WhitelistConfig, WhitelistEntry};

    let config = SentinelConfig {
        suspicion_threshold: 0.7,
        min_value_wei: one_eth(),
        min_gas_used: 500_000,
        min_erc20_transfers: 5,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
        mev_flash_loan_factor: 1.0,
        mev_selfdestruct_factor: 1.0,
    };
    let wl = WhitelistEngine::new(WhitelistConfig {
        entries: vec![
            WhitelistEntry {
                address: balancer_vault(),
                protocol: "Balancer Vault".into(),
                category: WhitelistCategory::FlashLoan,
                score_modifier: -0.4,
            },
            WhitelistEntry {
                address: aave_v3(),
                protocol: "Aave V3 Pool".into(),
                category: WhitelistCategory::Lending,
                score_modifier: -0.35,
            },
            WhitelistEntry {
                address: aave_v2(),
                protocol: "Aave V2 Pool".into(),
                category: WhitelistCategory::Lending,
                score_modifier: -0.35,
            },
            WhitelistEntry {
                address: uniswap_v3_router_addr(),
                protocol: "Uniswap V3 Router".into(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            },
            WhitelistEntry {
                address: uniswap_v2_router(),
                protocol: "Uniswap V2 Router".into(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            },
            WhitelistEntry {
                address: oneinch_v5(),
                protocol: "1inch V5 Router".into(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            },
            WhitelistEntry {
                address: sushiswap(),
                protocol: "SushiSwap Router".into(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            },
        ],
    });
    let filter = PreFilter::with_whitelist(config, wl);
    let cases = all_cases();
    let m = run_benchmark(&filter, &cases);

    print_matrix("With Whitelist (threshold=0.7)", &m);
}

/// Detailed per-case diagnostic: shows score, reasons, relevance/symmetry factors.
#[test]
fn prefilter_benchmark_diagnostic() {
    let config = SentinelConfig {
        suspicion_threshold: 0.7,
        min_value_wei: one_eth(),
        min_gas_used: 500_000,
        min_erc20_transfers: 5,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
        mev_flash_loan_factor: 1.0,
        mev_selfdestruct_factor: 1.0,
    };
    let filter = PreFilter::new(config);
    let header = make_header(20_000_000);
    let cases = all_cases();

    println!("\n=== Per-Case Diagnostic (threshold=0.7) ===");
    println!(
        "{:<55} {:>6} {:>8} {:>7} {}",
        "Case", "Attack", "Detected", "Score", "Reasons"
    );
    println!("{}", "-".repeat(120));

    for case in &cases {
        let result = filter.scan_tx(&case.tx, &case.receipt, 0, &header);
        let (detected, score, reasons) = match &result {
            Some(stx) => {
                let reasons: Vec<String> = stx
                    .reasons
                    .iter()
                    .map(|r| match r {
                        SuspicionReason::FlashLoanSignature { .. } => "H1:flash".into(),
                        SuspicionReason::HighValueWithRevert { .. } => "H2:revert".into(),
                        SuspicionReason::MultipleErc20Transfers { count } => {
                            format!("H3:erc20({count})")
                        }
                        SuspicionReason::KnownContractInteraction { label, .. } => {
                            format!("H4:{label}")
                        }
                        SuspicionReason::UnusualGasPattern { .. } => "H5:gas".into(),
                        SuspicionReason::SelfDestructDetected => "H6:selfdestruct".into(),
                        SuspicionReason::PriceOracleWithSwap { .. } => "H7:oracle+dex".into(),
                        SuspicionReason::AsymmetricCashFlow {
                            unique_destinations,
                        } => {
                            format!("H8:asymmetric({unique_destinations})")
                        }
                        SuspicionReason::AccessControlBypass { score } => {
                            format!("H9:acb({score:.2})")
                        }
                    })
                    .collect();
                (true, stx.score, reasons.join(", "))
            }
            None => (false, 0.0, "-".into()),
        };

        let label = if case.is_attack { "ATTACK" } else { "NORMAL" };
        let status = match (case.is_attack, detected) {
            (true, true) => "TP",
            (true, false) => "FN !!",
            (false, true) => "FP !!",
            (false, false) => "TN",
        };
        println!(
            "{:<55} {:>6} {:>8} {:>7.2} {}",
            case.name, label, status, score, reasons
        );
    }
}
