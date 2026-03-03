//! Live Reentrancy Detection Demo
//!
//! Demonstrates the full 6-phase attack detection pipeline:
//!   Phase 1: Deploy & Execute real reentrancy bytecodes in LEVM
//!   Phase 2: Verify the attack happened (call depth, SSTOREs)
//!   Phase 3: AttackClassifier detects Reentrancy pattern
//!   Phase 4: FundFlowTracer traces ETH transfers
//!   Phase 5: SentinelService processes the real receipt
//!   Phase 6: Alert validation
//!
//! Run: cargo run -p argus --features "sentinel,autopsy" --example reentrancy_demo

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use ethrex_common::constants::EMPTY_TRIE_HASH;
use ethrex_common::types::{
    Account, Block, BlockBody, BlockHeader, Code, EIP1559Transaction, Receipt, Transaction, TxKind,
    TxType,
};
use ethrex_common::{Address, U256};
use ethrex_levm::Environment;
use ethrex_levm::db::gen_db::GeneralizedDatabase;
use ethrex_storage::{EngineType, Store};
use rustc_hash::FxHashMap;

use argus::autopsy::classifier::AttackClassifier;
use argus::autopsy::fund_flow::FundFlowTracer;
use argus::autopsy::types::AttackPattern;
use argus::engine::ReplayEngine;
use argus::sentinel::service::{AlertHandler, SentinelService};
use argus::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelConfig};
use argus::types::ReplayConfig;

// ── Helpers ──────────────────────────────────────────────────────────────

fn big_balance() -> U256 {
    U256::from(10).pow(U256::from(30))
}

fn make_test_db(accounts: Vec<(Address, Code)>) -> GeneralizedDatabase {
    let store = Store::new("", EngineType::InMemory).expect("in-memory store");
    let header = BlockHeader {
        state_root: *EMPTY_TRIE_HASH,
        ..Default::default()
    };
    let vm_db: ethrex_vm::DynVmDatabase = Box::new(
        ethrex_blockchain::vm::StoreVmDatabase::new(store, header).expect("StoreVmDatabase"),
    );
    let balance = big_balance();
    let mut cache = FxHashMap::default();
    for (addr, code) in accounts {
        cache.insert(addr, Account::new(balance, code, 0, FxHashMap::default()));
    }
    GeneralizedDatabase::new_with_account_state(Arc::new(vm_db), cache)
}

/// Victim: sends 1 wei to CALLER, then SSTORE slot 0 = 1 (vulnerable order).
fn victim_bytecode() -> Vec<u8> {
    vec![
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // retLen retOff argsLen argsOff
        0x60, 0x01, // value = 1 wei
        0x33, // CALLER
        0x61, 0xFF, 0xFF, // gas = 0xFFFF
        0xF1, // CALL
        0x50, // POP
        0x60, 0x01, 0x60, 0x00, 0x55, // SSTORE(0, 1)
        0x00, // STOP
    ]
}

/// Attacker: counter in slot 0. if counter < 2: increment + CALL victim.
fn attacker_bytecode(victim_addr: Address) -> Vec<u8> {
    let v = victim_addr.as_bytes()[19];
    vec![
        0x60, 0x00, 0x54, // SLOAD(0) → counter
        0x80, 0x60, 0x02, 0x11, 0x15, // DUP1, PUSH1 2, GT, ISZERO
        0x60, 0x23, 0x57, // PUSH1 0x23, JUMPI (if counter >= 2 → exit)
        0x60, 0x01, 0x01, 0x60, 0x00, 0x55, // counter+1, SSTORE
        0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, // retLen retOff argsLen argsOff
        0x60, 0x00, // value = 0
        0x60, v, // victim address
        0x61, 0xFF, 0xFF, // gas = 0xFFFF
        0xF1, 0x50, 0x00, // CALL, POP, STOP
        0x5B, 0x50, 0x00, // JUMPDEST, POP, STOP
    ]
}

// ── Alert Handler ────────────────────────────────────────────────────────

struct DemoAlertHandler {
    count: Arc<AtomicUsize>,
    alerts: Arc<std::sync::Mutex<Vec<SentinelAlert>>>,
}

impl AlertHandler for DemoAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        self.count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut v) = self.alerts.lock() {
            v.push(alert);
        }
    }
}

// ── Main ─────────────────────────────────────────────────────────────────

fn main() {
    println!();
    println!("================================================================");
    println!("  Live Reentrancy Attack Detection — Full Pipeline Demo");
    println!("================================================================");
    println!();

    // ── Phase 1: Deploy & Execute ────────────────────────────────────────
    println!("Phase 1  Deploy & Execute");
    println!("----------------------------------------------------------------");

    let attacker_addr = Address::from_low_u64_be(0x42);
    let victim_addr = Address::from_low_u64_be(0x43);
    let sender_addr = Address::from_low_u64_be(0x100);

    println!("  Sender:   {sender_addr:?}");
    println!(
        "  Attacker: {attacker_addr:?}  ({} bytes)",
        attacker_bytecode(victim_addr).len()
    );
    println!(
        "  Victim:   {victim_addr:?}  ({} bytes)",
        victim_bytecode().len()
    );

    let accounts = vec![
        (
            attacker_addr,
            Code::from_bytecode(Bytes::from(attacker_bytecode(victim_addr))),
        ),
        (
            victim_addr,
            Code::from_bytecode(Bytes::from(victim_bytecode())),
        ),
        (sender_addr, Code::from_bytecode(Bytes::new())),
    ];

    let mut db = make_test_db(accounts);
    let env = Environment {
        origin: sender_addr,
        gas_limit: 10_000_000,
        block_gas_limit: 10_000_000,
        ..Default::default()
    };
    let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(attacker_addr),
        data: Bytes::new(),
        ..Default::default()
    });

    let engine =
        ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default()).expect("execution failed");

    let trace = engine.trace();
    let steps = engine.steps_range(0, engine.len());

    println!(
        "  Execution: {} (gas_used={})",
        if trace.success { "SUCCESS" } else { "REVERTED" },
        trace.gas_used
    );
    println!("  Opcode steps recorded: {}", engine.len());
    println!();

    // ── Phase 2: Verify Attack ───────────────────────────────────────────
    println!("Phase 2  Verify Attack");
    println!("----------------------------------------------------------------");

    let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);
    let sstore_count = steps.iter().filter(|s| s.opcode == 0x55).count();
    let call_count = steps.iter().filter(|s| s.opcode == 0xF1).count();

    println!("  Max call depth: {max_depth}  (need >= 3 for reentrancy)");
    println!("  CALL opcodes:   {call_count}");
    println!("  SSTORE opcodes: {sstore_count}  (attacker counter writes)");

    // Show call flow
    println!();
    println!("  Call Flow:");
    let mut prev_depth = 0;
    for step in steps.iter() {
        if step.depth != prev_depth || step.opcode == 0xF1 || step.opcode == 0x55 {
            if step.opcode == 0xF1 {
                let indent = "    ".repeat(step.depth + 1);
                println!("{indent}depth={} CALL  (contract calling out)", step.depth);
            } else if step.opcode == 0x55 {
                let indent = "    ".repeat(step.depth + 1);
                println!("{indent}depth={} SSTORE (state write)", step.depth);
            }
            prev_depth = step.depth;
        }
    }
    println!();

    assert!(max_depth >= 3, "call depth too shallow");
    assert!(sstore_count >= 2, "not enough SSTOREs");
    println!("  Result: CONFIRMED — reentrancy pattern detected in trace");
    println!();

    // ── Phase 3: Classify ────────────────────────────────────────────────
    println!("Phase 3  AttackClassifier");
    println!("----------------------------------------------------------------");

    let detected = AttackClassifier::classify_with_confidence(steps);
    println!("  Patterns detected: {}", detected.len());

    for d in &detected {
        let name = match &d.pattern {
            AttackPattern::Reentrancy {
                target_contract, ..
            } => format!("Reentrancy (target={target_contract:?})"),
            AttackPattern::FlashLoan { .. } => "FlashLoan".to_string(),
            AttackPattern::PriceManipulation { .. } => "PriceManipulation".to_string(),
            AttackPattern::AccessControlBypass { .. } => "AccessControlBypass".to_string(),
        };
        println!("    {name}");
        println!("      confidence: {:.1}%", d.confidence * 100.0);
        for e in &d.evidence {
            println!("      evidence: {e}");
        }
    }

    let reentrancy = detected
        .iter()
        .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));
    assert!(reentrancy.is_some(), "classifier missed reentrancy");
    assert!(reentrancy.unwrap().confidence >= 0.7);
    println!();
    println!(
        "  Result: Reentrancy detected with {:.0}% confidence",
        reentrancy.unwrap().confidence * 100.0
    );
    println!();

    // ── Phase 4: Fund Flow ───────────────────────────────────────────────
    println!("Phase 4  FundFlowTracer");
    println!("----------------------------------------------------------------");

    let flows = FundFlowTracer::trace(steps);
    let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
    let erc20_flows: Vec<_> = flows.iter().filter(|f| f.token.is_some()).collect();

    println!(
        "  Total flows: {} (ETH: {}, ERC-20: {})",
        flows.len(),
        eth_flows.len(),
        erc20_flows.len()
    );

    for f in &eth_flows {
        println!(
            "    ETH  {:?} -> {:?}  ({} wei)  step #{}",
            f.from, f.to, f.value, f.step_index
        );
    }

    let victim_to_attacker = eth_flows
        .iter()
        .any(|f| f.from == victim_addr && f.to == attacker_addr);
    assert!(victim_to_attacker, "no victim->attacker flow");

    println!();
    println!("  Result: ETH drain confirmed (victim -> attacker)");
    println!();

    // ── Phase 5: Sentinel Pipeline ───────────────────────────────────────
    println!("Phase 5  SentinelService Pipeline");
    println!("----------------------------------------------------------------");

    let alert_count = Arc::new(AtomicUsize::new(0));
    let captured_alerts = Arc::new(std::sync::Mutex::new(Vec::<SentinelAlert>::new()));
    let handler = DemoAlertHandler {
        count: alert_count.clone(),
        alerts: captured_alerts.clone(),
    };

    let store = Store::new("", EngineType::InMemory).expect("store");
    let config = SentinelConfig {
        suspicion_threshold: 0.1,
        min_gas_used: 50_000,
        ..Default::default()
    };
    let analysis_config = AnalysisConfig {
        prefilter_alert_mode: true,
        ..Default::default()
    };

    let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

    let receipt = Receipt {
        tx_type: TxType::EIP1559,
        succeeded: trace.success,
        cumulative_gas_used: trace.gas_used,
        logs: vec![],
    };
    let tight_gas_limit = trace.gas_used + trace.gas_used / 20;

    println!(
        "  Receipt: succeeded={}, gas_used={}",
        trace.success, trace.gas_used
    );
    println!(
        "  TX gas_limit: {} (ratio: {:.1}%)",
        tight_gas_limit,
        trace.gas_used as f64 / tight_gas_limit as f64 * 100.0
    );
    println!("  Config: threshold=0.1, min_gas=50k, prefilter_alert_mode=true");

    let sentinel_tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        to: TxKind::Call(attacker_addr),
        gas_limit: tight_gas_limit,
        data: Bytes::new(),
        ..Default::default()
    });
    let block = Block {
        header: BlockHeader {
            number: 19_500_000,
            gas_used: trace.gas_used,
            gas_limit: 30_000_000,
            ..Default::default()
        },
        body: BlockBody {
            transactions: vec![sentinel_tx],
            ..Default::default()
        },
    };

    println!("  Feeding block #{} to SentinelService...", 19_500_000);

    use ethrex_blockchain::BlockObserver;
    service.on_block_committed(block, vec![receipt]);
    std::thread::sleep(std::time::Duration::from_millis(300));

    let count = alert_count.load(Ordering::SeqCst);
    println!("  Alerts emitted: {count}");
    println!();

    // ── Phase 6: Alert Validation ────────────────────────────────────────
    println!("Phase 6  Alert Validation");
    println!("----------------------------------------------------------------");

    let alerts = captured_alerts.lock().unwrap();
    if let Some(alert) = alerts.first() {
        println!("  Block:    #{}", alert.block_number);
        println!("  Priority: {:?}", alert.alert_priority);
        println!("  Score:    {:.2}", alert.suspicion_score);
        println!(
            "  Reasons:  {} suspicion reason(s)",
            alert.suspicion_reasons.len()
        );
        for r in &alert.suspicion_reasons {
            println!("    - {r:?}");
        }
        println!("  Summary:  {}", alert.summary);
    }

    let snap = service.metrics().snapshot();
    println!();
    println!("  Metrics:");
    println!("    blocks_scanned:  {}", snap.blocks_scanned);
    println!("    txs_scanned:     {}", snap.txs_scanned);
    println!("    txs_flagged:     {}", snap.txs_flagged);
    println!("    alerts_emitted:  {}", snap.alerts_emitted);
    println!();

    assert!(count >= 1);
    assert!(snap.alerts_emitted >= 1);

    println!("================================================================");
    println!("  ALL 6 PHASES PASSED — Full pipeline operational");
    println!("================================================================");
    println!();
}
