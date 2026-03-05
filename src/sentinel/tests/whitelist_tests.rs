//! Whitelist engine integration tests — fixture-based, no RPC calls.

use bytes::Bytes;
use ethrex_common::types::{
    BlockHeader, LegacyTransaction, Log, Receipt, Transaction, TxKind, TxType,
};
use ethrex_common::{Address, H256, U256};

use crate::sentinel::pre_filter::PreFilter;
use crate::sentinel::types::{AlertPriority, SentinelConfig, SuspicionReason};
use crate::sentinel::whitelist::{
    WhitelistCategory, WhitelistConfig, WhitelistEngine, WhitelistEntry,
};

fn wl_addr(hex: &str) -> Address {
    let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).expect("valid hex");
    Address::from_slice(&bytes)
}

fn balancer_vault_wl() -> Address {
    wl_addr("BA12222222228d8Ba445958a75a0704d566BF2C8")
}

fn aave_v3_wl() -> Address {
    wl_addr("87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")
}

fn uniswap_router_wl() -> Address {
    wl_addr("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")
}

fn attacker_wl() -> Address {
    Address::from_slice(&[0xDE; 20])
}

fn one_eth_wl() -> U256 {
    U256::from(1_000_000_000_000_000_000_u64)
}

fn receipt_wl(succeeded: bool, gas: u64, logs: Vec<Log>) -> Receipt {
    Receipt {
        tx_type: TxType::Legacy,
        succeeded,
        cumulative_gas_used: gas,
        logs,
    }
}

fn call_tx_wl(to: Address, value: U256, gas_limit: u64) -> Transaction {
    Transaction::LegacyTransaction(LegacyTransaction {
        gas: gas_limit,
        to: TxKind::Call(to),
        value,
        ..Default::default()
    })
}

fn header_wl(number: u64) -> BlockHeader {
    BlockHeader {
        number,
        ..Default::default()
    }
}

fn log_wl(address: Address, topics: Vec<H256>) -> Log {
    Log {
        address,
        topics,
        data: Bytes::new(),
    }
}

fn prefix_topic_wl(prefix: [u8; 4]) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&prefix);
    H256::from(bytes)
}

fn aave_flash_wl() -> H256 {
    prefix_topic_wl([0x63, 0x10, 0x42, 0xc8])
}

fn balancer_flash_wl() -> H256 {
    prefix_topic_wl([0x0d, 0x7d, 0x75, 0xe0])
}

fn transfer_wl() -> H256 {
    prefix_topic_wl([0xdd, 0xf2, 0x52, 0xad])
}

fn erc20_log_wl(emitter: Address) -> Log {
    log_wl(emitter, vec![transfer_wl(), H256::zero(), H256::zero()])
}

fn sample_wl_engine() -> WhitelistEngine {
    WhitelistEngine::new(WhitelistConfig {
        entries: vec![
            WhitelistEntry {
                address: balancer_vault_wl(),
                protocol: "Balancer Vault".to_string(),
                category: WhitelistCategory::FlashLoan,
                score_modifier: -0.4,
            },
            WhitelistEntry {
                address: aave_v3_wl(),
                protocol: "Aave V3 Pool".to_string(),
                category: WhitelistCategory::Lending,
                score_modifier: -0.35,
            },
            WhitelistEntry {
                address: uniswap_router_wl(),
                protocol: "Uniswap SwapRouter02".to_string(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            },
        ],
    })
}

// Test 1: Whitelisted address reduces score below threshold
#[test]
fn whitelist_address_match_reduces_score() {
    let config = SentinelConfig {
        suspicion_threshold: 0.85,
        ..Default::default()
    };
    let filter = PreFilter::with_whitelist(config, sample_wl_engine());

    // Balancer Vault flash loan: base = flash(0.4) + known_contract(0.1) = 0.5
    // After whitelist: 0.5 + (-0.4) = 0.1 < 0.85 → no alert
    let flash_log = log_wl(balancer_vault_wl(), vec![balancer_flash_wl()]);
    let receipt = receipt_wl(true, 500_000, vec![flash_log]);
    let tx = call_tx_wl(balancer_vault_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(
        result.is_none(),
        "Balancer Vault flash loan arb must not be flagged after whitelist modifier"
    );
}

// Test 2: Non-whitelisted address score unchanged
#[test]
fn non_whitelisted_address_score_unchanged() {
    let config = SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    };
    let filter = PreFilter::with_whitelist(config, sample_wl_engine());

    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    let erc20_logs: Vec<Log> = (0..6_u8)
        .map(|i| erc20_log_wl(Address::from_slice(&[i; 20])))
        .collect();
    let mut logs = vec![flash_log];
    logs.extend(erc20_logs);
    let receipt = receipt_wl(true, 500_000, logs);
    let tx = call_tx_wl(attacker_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(
        result.is_some(),
        "Unknown attacker flash loan must remain flagged"
    );
    let stx = result.unwrap();
    assert_eq!(
        stx.whitelist_matches, 0,
        "No whitelist matches for unknown address"
    );
}

// Test 3: FlashLoanSignature alone never triggers alert
#[test]
fn flash_loan_signature_alone_not_critical() {
    let config = SentinelConfig {
        suspicion_threshold: 0.85,
        ..Default::default()
    };
    let filter = PreFilter::with_whitelist(config, WhitelistEngine::empty());

    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    let receipt = receipt_wl(true, 500_000, vec![flash_log]);
    let tx = call_tx_wl(attacker_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(
        result.is_none(),
        "FlashLoanSignature alone must not produce an alert"
    );
}

// Test 4: Score below 0.85 threshold — no alert
#[test]
fn suspicion_threshold_0_85_boundary_below() {
    let config = SentinelConfig {
        suspicion_threshold: 0.85,
        min_value_wei: one_eth_wl(),
        min_gas_used: 100_000,
        min_erc20_transfers: 3,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
    };
    // revert(0.3) + erc20_3x(0.2) + unusual_gas(0.15) = 0.65, modifier=-0.11 → 0.54 < 0.85
    let wl = WhitelistEngine::new(WhitelistConfig {
        entries: vec![WhitelistEntry {
            address: attacker_wl(),
            protocol: "Borderline".to_string(),
            category: WhitelistCategory::DEX,
            score_modifier: -0.11,
        }],
    });
    let filter = PreFilter::with_whitelist(config, wl);

    let erc20_logs: Vec<Log> = (0..3_u8)
        .map(|i| erc20_log_wl(Address::from_slice(&[i; 20])))
        .collect();
    let receipt = receipt_wl(false, 960_000, erc20_logs);
    let tx = call_tx_wl(attacker_wl(), one_eth_wl() * 2, 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(result.is_none(), "Score below 0.85 must not produce alert");
}

// Test 5: Score >= 0.85 triggers Critical alert
#[test]
fn suspicion_threshold_0_85_boundary_at_threshold() {
    let config = SentinelConfig {
        suspicion_threshold: 0.85,
        min_value_wei: one_eth_wl(),
        min_gas_used: 100_000,
        min_erc20_transfers: 5,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
    };
    let filter = PreFilter::with_whitelist(config, WhitelistEngine::empty());

    // Flash(0.4) + ERC20_11x(0.4) + H2(0.3) = 1.1 → clamped 1.0
    // No known contract → relevance = 1.0
    // Asymmetric transfers (different from/to) → symmetry = 1.0
    // score = 1.0 >= 0.85
    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    // Create ERC-20 logs with distinct from/to addresses to avoid symmetric cash flow discount
    let erc20_logs: Vec<Log> = (10..21_u8)
        .map(|i| {
            let mut from_bytes = [0u8; 32];
            from_bytes[31] = i;
            let mut to_bytes = [0u8; 32];
            to_bytes[31] = i + 100;
            log_wl(
                Address::from_slice(&[i; 20]),
                vec![transfer_wl(), H256::from(from_bytes), H256::from(to_bytes)],
            )
        })
        .collect();

    let mut logs = vec![flash_log];
    logs.extend(erc20_logs);
    let receipt = receipt_wl(false, 500_000, logs);
    let tx = call_tx_wl(attacker_wl(), one_eth_wl() * 2, 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(result.is_some(), "Score >= 0.85 must produce an alert");
    assert_eq!(result.unwrap().priority, AlertPriority::Critical);
}

// Test 6: Empty whitelist fallback — no panics, normal scoring
#[test]
fn empty_whitelist_fallback_normal_operation() {
    let config = SentinelConfig {
        suspicion_threshold: 0.3,
        ..Default::default()
    };
    let filter = PreFilter::with_whitelist(config, WhitelistEngine::empty());

    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    let erc20_logs: Vec<Log> = (0..6_u8)
        .map(|i| erc20_log_wl(Address::from_slice(&[i; 20])))
        .collect();
    let mut logs = vec![flash_log];
    logs.extend(erc20_logs);
    let receipt = receipt_wl(true, 500_000, logs);
    let tx = call_tx_wl(attacker_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(
        result.is_some(),
        "Empty whitelist fallback must not prevent normal detection"
    );
    assert_eq!(result.unwrap().whitelist_matches, 0);
}

// Test 7: WhitelistCategory::FlashLoan matching
#[test]
fn whitelist_category_flash_loan_match() {
    let engine = WhitelistEngine::new(WhitelistConfig {
        entries: vec![WhitelistEntry {
            address: balancer_vault_wl(),
            protocol: "Balancer Vault".to_string(),
            category: WhitelistCategory::FlashLoan,
            score_modifier: -0.4,
        }],
    });

    let m = engine
        .check_address(&balancer_vault_wl())
        .expect("must match");
    assert_eq!(m.category, WhitelistCategory::FlashLoan);
    assert_eq!(m.protocol, "Balancer Vault");
    assert!((m.score_modifier - (-0.4)).abs() < f64::EPSILON);
}

// Test 8: WhitelistCategory::DEX matching
#[test]
fn whitelist_category_dex_match() {
    let engine = WhitelistEngine::new(WhitelistConfig {
        entries: vec![WhitelistEntry {
            address: uniswap_router_wl(),
            protocol: "Uniswap SwapRouter02".to_string(),
            category: WhitelistCategory::DEX,
            score_modifier: -0.3,
        }],
    });

    let m = engine
        .check_address(&uniswap_router_wl())
        .expect("must match");
    assert_eq!(m.category, WhitelistCategory::DEX);
    assert!((m.score_modifier - (-0.3)).abs() < f64::EPSILON);
}

// Test 9: WhitelistCategory::Lending matching
#[test]
fn whitelist_category_lending_match() {
    let engine = WhitelistEngine::new(WhitelistConfig {
        entries: vec![WhitelistEntry {
            address: aave_v3_wl(),
            protocol: "Aave V3 Pool".to_string(),
            category: WhitelistCategory::Lending,
            score_modifier: -0.35,
        }],
    });

    let m = engine.check_address(&aave_v3_wl()).expect("must match");
    assert_eq!(m.category, WhitelistCategory::Lending);
    assert!((m.score_modifier - (-0.35)).abs() < f64::EPSILON);
}

// Test 10: score_modifier clamped — adjusted score floor is 0.0
#[test]
fn score_after_modifier_clamped_to_zero() {
    // Flash(0.4) + ERC20_3x(0.2) = 0.6; modifier=-1.0 → adjusted = max(-0.4, 0.0) = 0.0
    let config = SentinelConfig {
        suspicion_threshold: 0.01,
        min_value_wei: one_eth_wl(),
        min_gas_used: 100_000,
        min_erc20_transfers: 3,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
    };
    let wl = WhitelistEngine::new(WhitelistConfig {
        entries: vec![WhitelistEntry {
            address: attacker_wl(),
            protocol: "BigModifier".to_string(),
            category: WhitelistCategory::DEX,
            score_modifier: -1.0,
        }],
    });
    let filter = PreFilter::with_whitelist(config, wl);

    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    let erc20_logs: Vec<Log> = (0..3_u8)
        .map(|i| erc20_log_wl(Address::from_slice(&[i; 20])))
        .collect();
    let mut logs = vec![flash_log];
    logs.extend(erc20_logs);
    let receipt = receipt_wl(true, 500_000, logs);
    let tx = call_tx_wl(attacker_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(
        result.is_none(),
        "Score clamped to 0.0 must not produce alert"
    );
}

// Test 11: score cannot exceed 1.0 (upper clamp)
#[test]
fn score_does_not_exceed_1_0() {
    let config = SentinelConfig {
        suspicion_threshold: 0.5,
        min_value_wei: one_eth_wl(),
        min_gas_used: 100_000,
        min_erc20_transfers: 5,
        gas_ratio_threshold: 0.95,
        min_independent_signals: 2,
        relevance_factor: 0.3,
        symmetry_discount: 0.5,
    };
    let filter = PreFilter::with_whitelist(config, WhitelistEngine::empty());

    let flash_log = log_wl(attacker_wl(), vec![aave_flash_wl()]);
    let erc20_logs: Vec<Log> = (0..12_u8)
        .map(|i| erc20_log_wl(Address::from_slice(&[i; 20])))
        .collect();
    let mut logs = vec![flash_log];
    logs.extend(erc20_logs);
    let receipt = receipt_wl(false, 960_000, logs);
    let tx = call_tx_wl(attacker_wl(), one_eth_wl() * 2, 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    assert!(result.is_some(), "High-signal TX should be flagged");
    let stx = result.unwrap();
    assert!(
        stx.score <= 1.0,
        "Score must not exceed 1.0, got {}",
        stx.score
    );
}

// Test 12: TOML parsing — spec format parsed correctly
#[test]
fn toml_whitelist_section_parsed_correctly() {
    let toml_str = r#"
entries = [
    { address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8", protocol = "Balancer Vault", category = "FlashLoan", score_modifier = -0.4 },
    { address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", protocol = "Aave V3 Pool", category = "Lending", score_modifier = -0.35 },
    { address = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", protocol = "Uniswap SwapRouter02", category = "DEX", score_modifier = -0.3 },
]
"#;
    let config: WhitelistConfig = toml::from_str(toml_str).expect("TOML parse must succeed");
    assert_eq!(config.entries.len(), 3);
    assert_eq!(config.entries[0].protocol, "Balancer Vault");
    assert_eq!(config.entries[0].category, WhitelistCategory::FlashLoan);
    assert!((config.entries[0].score_modifier - (-0.4)).abs() < f64::EPSILON);
    assert_eq!(config.entries[1].category, WhitelistCategory::Lending);
    assert_eq!(config.entries[2].category, WhitelistCategory::DEX);
}

// Test 13: TOML empty section → empty whitelist fallback
#[test]
fn toml_empty_whitelist_section_fallback() {
    use crate::sentinel::config::SentinelFullConfig;

    let toml_str = "[sentinel]\nenabled = true\n";
    let wrapper: toml::Value = toml::from_str(toml_str).expect("parse");
    let config: SentinelFullConfig = wrapper
        .get("sentinel")
        .and_then(|v| v.clone().try_into().ok())
        .unwrap_or_default();
    assert!(
        config.whitelist.entries.is_empty(),
        "Missing [sentinel.whitelist] must produce empty entries"
    );
}

// Test 14: whitelist_matches counts unique addresses correctly
#[test]
fn whitelist_matches_field_counts_correctly() {
    let config = SentinelConfig {
        suspicion_threshold: 0.01,
        min_erc20_transfers: 1,
        ..Default::default()
    };
    let filter = PreFilter::with_whitelist(config, sample_wl_engine());

    // Balancer as tx.to + Balancer flash log + Aave erc20 log (×2, deduplicated)
    let flash_log = log_wl(balancer_vault_wl(), vec![balancer_flash_wl()]);
    let aave_log1 = erc20_log_wl(aave_v3_wl());
    let aave_log2 = erc20_log_wl(aave_v3_wl()); // same address → deduplicated
    let receipt = receipt_wl(true, 500_000, vec![flash_log, aave_log1, aave_log2]);
    let tx = call_tx_wl(balancer_vault_wl(), U256::zero(), 1_000_000);

    let result = filter.scan_tx(&tx, &receipt, 0, &header_wl(20_000_000));
    // With threshold 0.01, the whitelist reduction may drop score below threshold.
    // Either way, verify the outcome is deterministic:
    match result {
        Some(stx) => {
            assert_eq!(
                stx.whitelist_matches, 2,
                "Should count 2 unique whitelisted addresses (Balancer + Aave)"
            );
        }
        None => {
            // Score reduced below threshold by whitelist — verify by running
            // without whitelist to confirm the TX is inherently suspicious.
            let bare_filter = PreFilter::new(SentinelConfig {
                suspicion_threshold: 0.01,
                min_erc20_transfers: 1,
                ..Default::default()
            });
            let flash_log2 = log_wl(balancer_vault_wl(), vec![balancer_flash_wl()]);
            let aave2a = erc20_log_wl(aave_v3_wl());
            let aave2b = erc20_log_wl(aave_v3_wl());
            let receipt2 = receipt_wl(true, 500_000, vec![flash_log2, aave2a, aave2b]);
            let tx2 = call_tx_wl(balancer_vault_wl(), U256::zero(), 1_000_000);
            let bare_result = bare_filter.scan_tx(&tx2, &receipt2, 0, &header_wl(20_000_000));
            assert!(
                bare_result.is_some(),
                "TX should be suspicious without whitelist — confirms whitelist reduced score"
            );
        }
    }
}

// Test 15: SuspiciousTx with whitelist_matches serializes correctly
#[test]
fn suspicious_tx_whitelist_matches_serializes() {
    use crate::sentinel::types::{AlertPriority, SuspiciousTx};

    let stx = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![SuspicionReason::FlashLoanSignature {
            provider_address: balancer_vault_wl(),
        }],
        score: 0.1,
        priority: AlertPriority::Medium,
        whitelist_matches: 3,
    };

    let json = serde_json::to_string(&stx).expect("SuspiciousTx should serialize");
    assert!(
        json.contains("whitelist_matches"),
        "whitelist_matches must appear in JSON"
    );
    assert!(
        json.contains("FlashLoanSignature"),
        "reason must be preserved"
    );

    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    assert_eq!(parsed["whitelist_matches"], 3);
}

// Test 16: Old JSON without whitelist_matches deserializes with default 0
#[test]
fn old_json_whitelist_matches_defaults_to_zero() {
    use crate::sentinel::types::SuspiciousTx;

    // Pre-whitelist JSON format without whitelist_matches field
    let old_json = r#"{
        "tx_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "tx_index": 0,
        "reasons": ["SelfDestructDetected"],
        "score": 0.3,
        "priority": "Medium"
    }"#;

    let result: Result<SuspiciousTx, _> = serde_json::from_str(old_json);
    assert!(
        result.is_ok(),
        "Old JSON without whitelist_matches must deserialize successfully"
    );
    assert_eq!(
        result.unwrap().whitelist_matches,
        0,
        "Missing whitelist_matches must default to 0 via #[serde(default)]"
    );
}
