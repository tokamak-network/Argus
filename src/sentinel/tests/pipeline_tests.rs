//! Cross-module integration tests: AlertDispatcher, History, Metrics, WebSocket,
//! reentrancy bytecode detection, and live reentrancy pipeline.

// ===========================================================================
// H-5: Integration tests — cross-module wiring
// ===========================================================================

mod h5_integration_tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ethrex_common::{H256, U256};

    use crate::sentinel::alert::{AlertDispatcher, JsonlFileAlertHandler};
    use crate::sentinel::history::{AlertHistory, AlertQueryParams, SortOrder};
    use crate::sentinel::metrics::SentinelMetrics;
    use crate::sentinel::service::AlertHandler;
    use crate::sentinel::types::{AlertPriority, SentinelAlert};
    use crate::sentinel::ws_broadcaster::{WsAlertBroadcaster, WsAlertHandler};

    /// Atomic counter for unique temp file paths across tests.
    static H5_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_jsonl_path() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("sentinel_h5_integration");
        let _ = std::fs::create_dir_all(&dir);
        let id = H5_FILE_COUNTER.fetch_add(1, Ordering::SeqCst);
        dir.join(format!("h5_{}_{}.jsonl", std::process::id(), id))
    }

    fn make_alert(block_number: u64, priority: AlertPriority, tx_hash_byte: u8) -> SentinelAlert {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = tx_hash_byte;
        SentinelAlert {
            block_number,
            block_hash: H256::zero(),
            tx_hash: H256::from(hash_bytes),
            tx_index: 0,
            alert_priority: priority,
            suspicion_reasons: vec![],
            suspicion_score: match priority {
                AlertPriority::Critical => 0.9,
                AlertPriority::High => 0.6,
                AlertPriority::Medium => 0.4,
            },
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            whitelist_matches: 0,
            summary: format!("H5 test alert block={}", block_number),
            total_steps: 100,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        }
    }

    /// H-5 Test 1: AlertDispatcher with WsAlertHandler — write via pipeline,
    /// verify WebSocket subscriber receives the alert.
    #[test]
    fn test_h5_ws_broadcaster_with_alert_dispatcher() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let rx = broadcaster.subscribe();

        let ws_handler = WsAlertHandler::new(broadcaster.clone());
        let dispatcher = AlertDispatcher::new(vec![Box::new(ws_handler)]);

        let alert = make_alert(500, AlertPriority::High, 0xAA);
        dispatcher.on_alert(alert);

        let msg = rx.recv().expect("subscriber should receive alert");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 500);
        assert_eq!(parsed["alert_priority"], "High");
    }

    /// H-5 Test 2: Write alerts via JsonlFileAlertHandler, then read back
    /// via AlertHistory.query() — full roundtrip.
    #[test]
    fn test_h5_history_roundtrip_with_jsonl() {
        let path = unique_jsonl_path();

        // Write phase: push 3 alerts through the JSONL handler
        let handler = JsonlFileAlertHandler::new(path.clone());
        handler.on_alert(make_alert(100, AlertPriority::Medium, 0x01));
        handler.on_alert(make_alert(101, AlertPriority::High, 0x02));
        handler.on_alert(make_alert(102, AlertPriority::Critical, 0x03));

        // Read phase: query back via AlertHistory
        let history = AlertHistory::new(path.clone());
        let result = history.query(&AlertQueryParams::default());

        assert_eq!(result.total_count, 3);
        assert_eq!(result.alerts.len(), 3);

        // Newest first (default sort)
        assert_eq!(result.alerts[0].block_number, 102);
        assert_eq!(result.alerts[1].block_number, 101);
        assert_eq!(result.alerts[2].block_number, 100);

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 3: Pagination consistency — 25 alerts, pages of 10, no duplicates.
    #[test]
    fn test_h5_history_pagination_consistency() {
        let path = unique_jsonl_path();

        let handler = JsonlFileAlertHandler::new(path.clone());
        for i in 0..25 {
            handler.on_alert(make_alert(200 + i, AlertPriority::High, i as u8));
        }

        let history = AlertHistory::new(path.clone());

        let p1 = history.query(&AlertQueryParams {
            page: 1,
            page_size: 10,
            ..Default::default()
        });
        let p2 = history.query(&AlertQueryParams {
            page: 2,
            page_size: 10,
            ..Default::default()
        });
        let p3 = history.query(&AlertQueryParams {
            page: 3,
            page_size: 10,
            ..Default::default()
        });

        // All pages report the same total
        assert_eq!(p1.total_count, 25);
        assert_eq!(p2.total_count, 25);
        assert_eq!(p3.total_count, 25);

        // Page sizes
        assert_eq!(p1.alerts.len(), 10);
        assert_eq!(p2.alerts.len(), 10);
        assert_eq!(p3.alerts.len(), 5);

        // Total pages
        assert_eq!(p1.total_pages, 3);

        // No duplicates across pages
        let mut all_blocks: Vec<u64> = Vec::new();
        all_blocks.extend(p1.alerts.iter().map(|a| a.block_number));
        all_blocks.extend(p2.alerts.iter().map(|a| a.block_number));
        all_blocks.extend(p3.alerts.iter().map(|a| a.block_number));

        let unique: HashSet<u64> = all_blocks.iter().copied().collect();
        assert_eq!(unique.len(), 25, "all 25 alerts should appear exactly once");

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 4: Metrics counters increment correctly under direct usage.
    #[test]
    fn test_h5_metrics_increment_during_processing() {
        let metrics = SentinelMetrics::new();

        // Simulate a processing cycle
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(50);
        metrics.increment_txs_flagged(3);
        metrics.increment_alerts_emitted();
        metrics.increment_alerts_emitted();
        metrics.add_prefilter_us(1200);
        metrics.add_deep_analysis_ms(45);

        let snap = metrics.snapshot();
        assert_eq!(snap.blocks_scanned, 1);
        assert_eq!(snap.txs_scanned, 50);
        assert_eq!(snap.txs_flagged, 3);
        assert_eq!(snap.alerts_emitted, 2);
        assert_eq!(snap.prefilter_total_us, 1200);
        assert_eq!(snap.deep_analysis_total_ms, 45);

        // Simulate second block
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(30);

        let snap2 = metrics.snapshot();
        assert_eq!(snap2.blocks_scanned, 2);
        assert_eq!(snap2.txs_scanned, 80);
        // Previous snapshot is frozen
        assert_eq!(snap.blocks_scanned, 1);
    }

    /// H-5 Test 5: 10 concurrent subscribers all receive the same broadcast.
    #[test]
    fn test_h5_ws_concurrent_subscribers() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());

        let receivers: Vec<_> = (0..10).map(|_| broadcaster.subscribe()).collect();

        let alert = make_alert(999, AlertPriority::Critical, 0xFF);
        broadcaster.broadcast(&alert);

        for (i, rx) in receivers.iter().enumerate() {
            let msg = rx
                .recv()
                .unwrap_or_else(|_| panic!("subscriber {} should receive", i));
            let parsed: serde_json::Value = serde_json::from_str(&msg).expect("valid JSON");
            assert_eq!(parsed["block_number"], 999);
            assert_eq!(parsed["alert_priority"], "Critical");
        }
    }

    /// H-5 Test 6: 500 alerts with varying blocks, query with block_range filter.
    #[test]
    fn test_h5_history_large_file() {
        let path = unique_jsonl_path();

        let handler = JsonlFileAlertHandler::new(path.clone());
        for i in 0u64..500 {
            let priority = match i % 3 {
                0 => AlertPriority::Medium,
                1 => AlertPriority::High,
                _ => AlertPriority::Critical,
            };
            handler.on_alert(make_alert(1000 + i, priority, (i % 256) as u8));
        }

        let history = AlertHistory::new(path.clone());

        // Query a narrow range: blocks 1200..1250 (inclusive) = 51 alerts
        let result = history.query(&AlertQueryParams {
            block_range: Some((1200, 1250)),
            page_size: 100,
            ..Default::default()
        });

        assert_eq!(result.total_count, 51);
        for alert in &result.alerts {
            assert!(
                alert.block_number >= 1200 && alert.block_number <= 1250,
                "block {} out of range",
                alert.block_number
            );
        }

        // Verify sort order (newest first by default)
        for window in result.alerts.windows(2) {
            assert!(
                window[0].block_number >= window[1].block_number,
                "should be sorted descending"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// H-5 Test 7: Prometheus text output contains expected metric lines.
    #[test]
    fn test_h5_metrics_prometheus_format_valid() {
        let metrics = SentinelMetrics::new();

        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_blocks_scanned();
        metrics.increment_txs_scanned(100);
        metrics.increment_txs_flagged(7);
        metrics.increment_alerts_emitted();
        metrics.increment_alerts_deduplicated();
        metrics.increment_alerts_rate_limited();
        metrics.add_prefilter_us(5000);
        metrics.add_deep_analysis_ms(250);

        let text = metrics.to_prometheus_text();

        // Verify expected values appear
        assert!(text.contains("sentinel_blocks_scanned 3"));
        assert!(text.contains("sentinel_txs_scanned 100"));
        assert!(text.contains("sentinel_txs_flagged 7"));
        assert!(text.contains("sentinel_alerts_emitted 1"));
        assert!(text.contains("sentinel_alerts_deduplicated 1"));
        assert!(text.contains("sentinel_alerts_rate_limited 1"));
        assert!(text.contains("sentinel_prefilter_total_us 5000"));
        assert!(text.contains("sentinel_deep_analysis_total_ms 250"));

        // Verify Prometheus format structure (HELP + TYPE per metric)
        let help_count = text.matches("# HELP").count();
        let type_count = text.matches("# TYPE").count();
        // 14 base metrics + 6 AI metrics (when ai_agent feature is enabled)
        #[cfg(feature = "ai_agent")]
        {
            assert_eq!(help_count, 20, "should have 20 HELP lines (14 base + 6 AI)");
            assert_eq!(type_count, 20, "should have 20 TYPE lines (14 base + 6 AI)");
        }
        #[cfg(not(feature = "ai_agent"))]
        {
            assert_eq!(help_count, 14, "should have 14 HELP lines");
            assert_eq!(type_count, 14, "should have 14 TYPE lines");
        }

        // Base metrics are all counters
        assert!(
            text.contains("# TYPE sentinel_blocks_scanned counter"),
            "base metrics should be counters"
        );
    }

    /// H-5 Test 8: Full pipeline wiring — AlertDispatcher with WsAlertHandler
    /// + JsonlFileAlertHandler, then verify both outputs work.
    #[test]
    fn test_h5_full_pipeline_with_all_handlers() {
        let path = unique_jsonl_path();

        // Set up WebSocket broadcaster
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let rx = broadcaster.subscribe();
        let ws_handler = WsAlertHandler::new(broadcaster);

        // Set up JSONL file handler
        let jsonl_handler = JsonlFileAlertHandler::new(path.clone());

        // Wire into dispatcher
        let dispatcher = AlertDispatcher::new(vec![Box::new(ws_handler), Box::new(jsonl_handler)]);

        // Emit 3 alerts through the pipeline
        dispatcher.on_alert(make_alert(300, AlertPriority::Medium, 0x01));
        dispatcher.on_alert(make_alert(301, AlertPriority::High, 0x02));
        dispatcher.on_alert(make_alert(302, AlertPriority::Critical, 0x03));

        // Verify WebSocket subscriber received all 3
        let ws_msg1: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let ws_msg2: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let ws_msg3: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();

        assert_eq!(ws_msg1["block_number"], 300);
        assert_eq!(ws_msg2["block_number"], 301);
        assert_eq!(ws_msg3["block_number"], 302);

        // Verify JSONL file contains all 3, readable via AlertHistory
        let history = AlertHistory::new(path.clone());
        let result = history.query(&AlertQueryParams {
            sort_order: SortOrder::Oldest,
            ..Default::default()
        });

        assert_eq!(result.total_count, 3);
        assert_eq!(result.alerts[0].block_number, 300);
        assert_eq!(result.alerts[1].block_number, 301);
        assert_eq!(result.alerts[2].block_number, 302);

        let _ = std::fs::remove_file(&path);
    }
}

// ===========================================================================
// Reentrancy E2E Demo — Proves the full attack detection pipeline works
// end-to-end with actual reentrancy contract bytecodes.
// ===========================================================================

/// Test 1: Bytecode-level reentrancy detection via AttackClassifier.
///
/// Executes actual attacker + victim contracts through LEVM, captures the
/// opcode trace, and verifies the classifier detects Reentrancy with
/// confidence >= 0.7.
#[cfg(feature = "autopsy")]
mod reentrancy_bytecode_tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use ethrex_common::constants::EMPTY_TRIE_HASH;
    use ethrex_common::types::{
        Account, BlockHeader, Code, EIP1559Transaction, Transaction, TxKind,
    };
    use ethrex_common::{Address, U256};
    use ethrex_levm::Environment;
    use ethrex_levm::db::gen_db::GeneralizedDatabase;
    use rustc_hash::FxHashMap;

    use crate::autopsy::classifier::AttackClassifier;
    use crate::autopsy::types::AttackPattern;
    use crate::engine::ReplayEngine;
    use crate::types::ReplayConfig;

    /// Gas limit — large enough for reentrancy but not overflowing.
    const TEST_GAS_LIMIT: u64 = 10_000_000;

    /// Large balance that won't overflow on small additions (unlike U256::MAX).
    fn big_balance() -> U256 {
        U256::from(10).pow(U256::from(30))
    }

    fn make_test_db(accounts: Vec<(Address, Code)>) -> GeneralizedDatabase {
        let store = ethrex_storage::Store::new("", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");
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

    /// Victim Contract (20 bytes):
    /// Sends 1 wei to CALLER via CALL, then SSTORE slot 0 = 1.
    /// Vulnerable: state update AFTER external call.
    ///
    /// Bytecode:
    ///   PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 1  CALLER  PUSH2 0xFFFF  CALL
    ///   POP  PUSH1 1  PUSH1 0  SSTORE  STOP
    fn victim_bytecode() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0 (retLen)
            0x60, 0x00, // PUSH1 0 (retOff)
            0x60, 0x00, // PUSH1 0 (argsLen)
            0x60, 0x00, // PUSH1 0 (argsOff)
            0x60, 0x01, // PUSH1 1 (value = 1 wei)
            0x33, // CALLER
            0x61, 0xFF, 0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP (return status)
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE(slot=0, value=1)
            0x00, // STOP
        ]
    }

    /// Attacker Contract (38 bytes):
    /// Counter in slot 0. If counter < 2: increment + CALL victim.
    /// If counter >= 2: STOP.
    ///
    /// Bytecode:
    ///   SLOAD(0)  DUP1  PUSH1 2  GT  ISZERO  PUSH1 0x23  JUMPI
    ///   PUSH1 1  ADD  PUSH1 0  SSTORE
    ///   PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0  PUSH1 0
    ///   PUSH1 <victim_lo>  PUSH2 0xFFFF  CALL  POP  STOP
    ///   JUMPDEST  POP  STOP
    fn attacker_bytecode(victim_addr: Address) -> Vec<u8> {
        // Extract low byte of victim address for PUSH1
        let victim_byte = victim_addr.as_bytes()[19];
        // Bytecode layout (byte offsets):
        //  0: PUSH1 0       2: SLOAD      3: DUP1       4: PUSH1 2
        //  6: GT            7: ISZERO     8: PUSH1 0x23  10: JUMPI
        // 11: PUSH1 1      13: ADD       14: PUSH1 0    16: SSTORE
        // 17: PUSH1 0 (retLen)  19: PUSH1 0 (retOff)  21: PUSH1 0 (argsLen)
        // 23: PUSH1 0 (argsOff) 25: PUSH1 0 (value)   27: PUSH1 victim
        // 29: PUSH2 0xFFFF 32: CALL      33: POP       34: STOP
        // 35: JUMPDEST      36: POP       37: STOP
        vec![
            0x60,
            0x00, // 0: PUSH1 0 (slot)
            0x54, // 2: SLOAD(0) → counter
            0x80, // 3: DUP1
            0x60,
            0x02, // 4: PUSH1 2
            0x11, // 6: GT — stack: [2, counter] → 2 > counter
            0x15, // 7: ISZERO — !(2 > counter) = counter >= 2
            0x60,
            0x23, // 8: PUSH1 0x23 = 35 (JUMPDEST offset)
            0x57, // 10: JUMPI (jump if counter >= 2)
            // counter < 2 path: increment + CALL victim
            0x60,
            0x01, // 11: PUSH1 1
            0x01, // 13: ADD (counter + 1)
            0x60,
            0x00, // 14: PUSH1 0
            0x55, // 16: SSTORE(slot=0, value=counter+1)
            // CALL victim(gas=0xFFFF, addr=victim, value=0, args=0,0, ret=0,0)
            0x60,
            0x00, // 17: PUSH1 0 (retLen)
            0x60,
            0x00, // 19: PUSH1 0 (retOff)
            0x60,
            0x00, // 21: PUSH1 0 (argsLen)
            0x60,
            0x00, // 23: PUSH1 0 (argsOff)
            0x60,
            0x00, // 25: PUSH1 0 (value)
            0x60,
            victim_byte, // 27: PUSH1 victim_addr
            0x61,
            0xFF,
            0xFF, // 29: PUSH2 0xFFFF (gas)
            0xF1, // 32: CALL
            0x50, // 33: POP
            0x00, // 34: STOP
            // counter >= 2 path
            0x5B, // 35: JUMPDEST
            0x50, // 36: POP (discard duplicated counter)
            0x00, // 37: STOP
        ]
    }

    #[test]
    fn reentrancy_bytecode_classifier_detects_attack() {
        let attacker_addr = Address::from_low_u64_be(0x42);
        let victim_addr = Address::from_low_u64_be(0x43);
        let sender_addr = Address::from_low_u64_be(0x100);

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
            gas_limit: TEST_GAS_LIMIT,
            block_gas_limit: TEST_GAS_LIMIT,
            ..Default::default()
        };
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(attacker_addr),
            data: Bytes::new(),
            ..Default::default()
        });

        let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())
            .expect("reentrancy TX should execute successfully");

        let steps = engine.steps_range(0, engine.len());

        // Verify trace has sufficient depth (attacker → victim → attacker re-entry)
        let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);
        assert!(
            max_depth >= 3,
            "Expected call depth >= 3 for reentrancy, got {max_depth}"
        );

        // Run the classifier
        let detected = AttackClassifier::classify_with_confidence(&steps);

        // Should find at least one Reentrancy pattern
        let reentrancy = detected
            .iter()
            .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));

        assert!(
            reentrancy.is_some(),
            "Classifier should detect reentrancy. Detected patterns: {detected:?}"
        );

        let reentrancy = reentrancy.unwrap();
        assert!(
            reentrancy.confidence >= 0.7,
            "Reentrancy confidence should be >= 0.7, got {}",
            reentrancy.confidence
        );

        // The classifier identifies re-entry by finding a contract that is called,
        // then called again before the first call completes. In our setup:
        //   sender → attacker → victim → attacker (re-entry!)
        // So the attacker is the contract being re-entered.
        if let AttackPattern::Reentrancy {
            target_contract, ..
        } = &reentrancy.pattern
        {
            assert_eq!(
                *target_contract, attacker_addr,
                "Reentrancy target should be the re-entered contract (attacker)"
            );
        }
    }
}

// ===========================================================================
// Live Reentrancy Pipeline — Full 6-phase E2E test with real bytecode execution.
//
// Unlike the mock-receipt tests above, this test:
//   1. Deploys actual attacker + victim contracts in LEVM
//   2. Executes the reentrancy attack and captures the opcode trace
//   3. Runs AttackClassifier + FundFlowTracer on the real trace
//   4. Feeds real execution results through the SentinelService pipeline
//   5. Verifies alerts and metrics end-to-end
// ===========================================================================

#[cfg(feature = "autopsy")]
mod live_reentrancy_pipeline_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use ethrex_common::constants::EMPTY_TRIE_HASH;
    use ethrex_common::types::{
        Account, Block, BlockBody, BlockHeader, Code, EIP1559Transaction, Receipt, Transaction,
        TxKind, TxType,
    };
    use ethrex_common::{Address, U256};
    use ethrex_levm::Environment;
    use ethrex_levm::db::gen_db::GeneralizedDatabase;
    use ethrex_storage::{EngineType, Store};
    use rustc_hash::FxHashMap;

    use crate::autopsy::classifier::AttackClassifier;
    use crate::autopsy::fund_flow::FundFlowTracer;
    use crate::autopsy::types::AttackPattern;
    use crate::engine::ReplayEngine;
    use crate::sentinel::service::{AlertHandler, SentinelService};
    use crate::sentinel::types::{AnalysisConfig, SentinelAlert, SentinelConfig};
    use crate::types::ReplayConfig;

    const TEST_GAS_LIMIT: u64 = 10_000_000;

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

    /// Victim: sends 1 wei to CALLER via CALL, then SSTORE slot 0 = 1.
    fn victim_bytecode() -> Vec<u8> {
        vec![
            0x60, 0x00, // PUSH1 0 (retLen)
            0x60, 0x00, // PUSH1 0 (retOff)
            0x60, 0x00, // PUSH1 0 (argsLen)
            0x60, 0x00, // PUSH1 0 (argsOff)
            0x60, 0x01, // PUSH1 1 (value = 1 wei)
            0x33, // CALLER
            0x61, 0xFF, 0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP
            0x60, 0x01, // PUSH1 1
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE(slot=0, value=1)
            0x00, // STOP
        ]
    }

    /// Attacker: counter in slot 0. If counter < 2: increment + CALL victim.
    fn attacker_bytecode(victim_addr: Address) -> Vec<u8> {
        let victim_byte = victim_addr.as_bytes()[19];
        vec![
            0x60,
            0x00, // PUSH1 0 (slot)
            0x54, // SLOAD(0)
            0x80, // DUP1
            0x60,
            0x02, // PUSH1 2
            0x11, // GT
            0x15, // ISZERO
            0x60,
            0x23, // PUSH1 0x23
            0x57, // JUMPI
            0x60,
            0x01, // PUSH1 1
            0x01, // ADD
            0x60,
            0x00, // PUSH1 0
            0x55, // SSTORE
            0x60,
            0x00, // PUSH1 0 (retLen)
            0x60,
            0x00, // PUSH1 0 (retOff)
            0x60,
            0x00, // PUSH1 0 (argsLen)
            0x60,
            0x00, // PUSH1 0 (argsOff)
            0x60,
            0x00, // PUSH1 0 (value)
            0x60,
            victim_byte, // PUSH1 victim
            0x61,
            0xFF,
            0xFF, // PUSH2 0xFFFF (gas)
            0xF1, // CALL
            0x50, // POP
            0x00, // STOP
            0x5B, // JUMPDEST
            0x50, // POP
            0x00, // STOP
        ]
    }

    struct CapturingAlertHandler {
        count: Arc<AtomicUsize>,
        alerts: Arc<std::sync::Mutex<Vec<SentinelAlert>>>,
    }

    impl AlertHandler for CapturingAlertHandler {
        fn on_alert(&self, alert: SentinelAlert) {
            self.count.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut v) = self.alerts.lock() {
                v.push(alert);
            }
        }
    }

    #[test]
    fn test_live_reentrancy_full_detection_pipeline() {
        // ---------------------------------------------------------------
        // Phase 1: Deploy & Execute — real reentrancy attack in LEVM
        // ---------------------------------------------------------------
        let attacker_addr = Address::from_low_u64_be(0x42);
        let victim_addr = Address::from_low_u64_be(0x43);
        let sender_addr = Address::from_low_u64_be(0x100);

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
            gas_limit: TEST_GAS_LIMIT,
            block_gas_limit: TEST_GAS_LIMIT,
            ..Default::default()
        };
        let tx = Transaction::EIP1559Transaction(EIP1559Transaction {
            to: TxKind::Call(attacker_addr),
            data: Bytes::new(),
            ..Default::default()
        });

        let engine = ReplayEngine::record(&mut db, env, &tx, ReplayConfig::default())
            .expect("reentrancy TX should execute successfully");

        let trace = engine.trace();
        let steps = engine.steps_range(0, engine.len());

        // ---------------------------------------------------------------
        // Phase 2: Verify Attack — call depth >= 3, SSTORE exists
        // ---------------------------------------------------------------
        let max_depth = steps.iter().map(|s| s.depth).max().unwrap_or(0);
        assert!(
            max_depth >= 3,
            "Expected call depth >= 3 for reentrancy, got {max_depth}"
        );

        let sstore_count = steps.iter().filter(|s| s.opcode == 0x55).count();
        assert!(
            sstore_count >= 2,
            "Expected at least 2 SSTOREs (attacker counter writes), got {sstore_count}"
        );

        // ---------------------------------------------------------------
        // Phase 3: Classify — AttackClassifier detects Reentrancy
        // ---------------------------------------------------------------
        let detected = AttackClassifier::classify_with_confidence(steps);

        let reentrancy = detected
            .iter()
            .find(|d| matches!(d.pattern, AttackPattern::Reentrancy { .. }));

        assert!(
            reentrancy.is_some(),
            "AttackClassifier should detect reentrancy on real trace. Detected: {detected:?}"
        );

        let reentrancy = reentrancy.unwrap();
        assert!(
            reentrancy.confidence >= 0.7,
            "Reentrancy confidence should be >= 0.7, got {}",
            reentrancy.confidence
        );

        if let AttackPattern::Reentrancy {
            target_contract, ..
        } = &reentrancy.pattern
        {
            assert_eq!(
                *target_contract, attacker_addr,
                "Reentrancy target should be the re-entered contract (attacker)"
            );
        }

        // ---------------------------------------------------------------
        // Phase 4: Fund Flow — ETH transfers from victim → attacker
        // ---------------------------------------------------------------
        let flows = FundFlowTracer::trace(steps);

        let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
        assert!(
            !eth_flows.is_empty(),
            "FundFlowTracer should detect ETH transfers (victim sends 1 wei per CALL)"
        );

        // Verify at least one flow goes from victim to attacker
        let victim_to_attacker = eth_flows
            .iter()
            .any(|f| f.from == victim_addr && f.to == attacker_addr);
        assert!(
            victim_to_attacker,
            "Should have ETH flow from victim ({victim_addr:?}) to attacker ({attacker_addr:?}). Flows: {eth_flows:?}"
        );

        // ---------------------------------------------------------------
        // Phase 5: Sentinel Pipeline — real receipt → SentinelService
        // ---------------------------------------------------------------
        let alert_count = Arc::new(AtomicUsize::new(0));
        let captured_alerts = Arc::new(std::sync::Mutex::new(Vec::<SentinelAlert>::new()));
        let handler = CapturingAlertHandler {
            count: alert_count.clone(),
            alerts: captured_alerts.clone(),
        };

        let store = Store::new("", EngineType::InMemory).expect("in-memory store");

        // Tuned config for stealthy reentrancy (1 wei value, ~82k gas):
        // - suspicion_threshold: 0.1 (production: 0.5, designed for loud attacks)
        // - min_gas_used: 50_000 (production: 500_000) — our attack uses ~82k gas
        // This demonstrates the pipeline works even for stealthy, low-gas attacks.
        let config = SentinelConfig {
            suspicion_threshold: 0.1,
            min_gas_used: 50_000,
            ..Default::default()
        };

        // prefilter_alert_mode: deep analysis can't replay from Store
        // (no genesis state) — emit lightweight alert from PreFilter.
        let analysis_config = AnalysisConfig {
            prefilter_alert_mode: true,
            ..Default::default()
        };

        let service = SentinelService::new(store, config, analysis_config, Box::new(handler));

        // Build receipt from real execution results
        let receipt = Receipt {
            tx_type: TxType::EIP1559,
            succeeded: trace.success,
            cumulative_gas_used: trace.gas_used,
            logs: vec![],
        };

        // Set gas_limit close to gas_used (>95% ratio) to trigger H5 gas anomaly
        let tight_gas_limit = trace.gas_used + trace.gas_used / 20; // ~105% of used
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

        use ethrex_blockchain::BlockObserver;
        service.on_block_committed(block, vec![receipt]);

        // Wait for worker thread to process
        std::thread::sleep(std::time::Duration::from_millis(300));

        // ---------------------------------------------------------------
        // Phase 6: Alert Validation — verify alert content + metrics
        // ---------------------------------------------------------------
        let count = alert_count.load(Ordering::SeqCst);
        assert!(
            count >= 1,
            "Expected at least 1 alert from sentinel pipeline, got {count}"
        );

        // Verify alert has suspicion reasons
        let alerts = captured_alerts.lock().unwrap();
        let alert = &alerts[0];
        assert!(
            !alert.suspicion_reasons.is_empty(),
            "Alert should have at least one suspicion reason"
        );
        assert!(
            alert.suspicion_score > 0.0,
            "Alert suspicion_score should be > 0, got {}",
            alert.suspicion_score
        );

        // Verify metrics
        let snap = service.metrics().snapshot();
        assert!(
            snap.blocks_scanned >= 1,
            "Expected blocks_scanned >= 1, got {}",
            snap.blocks_scanned
        );
        assert!(
            snap.txs_scanned >= 1,
            "Expected txs_scanned >= 1, got {}",
            snap.txs_scanned
        );
        assert!(
            snap.txs_flagged >= 1,
            "Expected txs_flagged >= 1, got {}",
            snap.txs_flagged
        );
        assert!(
            snap.alerts_emitted >= 1,
            "Expected alerts_emitted >= 1, got {}",
            snap.alerts_emitted
        );
    }
}
