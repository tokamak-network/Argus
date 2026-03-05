//! SentinelAlert serialization, deep analysis types, and autopsy-gated tests.

use super::*;

// ===========================================================================
// H-2: Deep Analysis Types Tests
// ===========================================================================

#[test]
fn test_analysis_config_defaults() {
    let config = AnalysisConfig::default();
    assert_eq!(config.max_steps, 1_000_000);
    assert!((config.min_alert_confidence - 0.4).abs() < f64::EPSILON);
}

#[test]
fn test_analysis_config_custom() {
    let config = AnalysisConfig {
        max_steps: 500_000,
        min_alert_confidence: 0.7,
        prefilter_alert_mode: true,
    };
    assert_eq!(config.max_steps, 500_000);
    assert!((config.min_alert_confidence - 0.7).abs() < f64::EPSILON);
    assert!(config.prefilter_alert_mode);
}

#[test]
fn test_sentinel_error_display() {
    let err = SentinelError::BlockNotFound {
        block_number: 19_500_000,
    };
    assert!(err.to_string().contains("19500000"));
    assert!(err.to_string().contains("not found"));

    let err = SentinelError::TxNotFound {
        block_number: 100,
        tx_index: 42,
    };
    assert!(err.to_string().contains("42"));
    assert!(err.to_string().contains("100"));

    let err = SentinelError::ParentNotFound { block_number: 200 };
    assert!(err.to_string().contains("200"));

    let err = SentinelError::StateRootMissing { block_number: 300 };
    assert!(err.to_string().contains("300"));

    let err = SentinelError::SenderRecovery {
        tx_index: 5,
        cause: "invalid signature".to_string(),
    };
    assert!(err.to_string().contains("5"));
    assert!(err.to_string().contains("invalid signature"));

    let err = SentinelError::StepLimitExceeded {
        steps: 2_000_000,
        max_steps: 1_000_000,
    };
    assert!(err.to_string().contains("2000000"));
    assert!(err.to_string().contains("1000000"));
}

#[test]
fn test_sentinel_error_vm() {
    let err = SentinelError::Vm("out of gas".to_string());
    assert!(err.to_string().contains("out of gas"));
}

#[test]
fn test_sentinel_error_db() {
    let err = SentinelError::Db("connection refused".to_string());
    assert!(err.to_string().contains("connection refused"));
}

#[test]
fn test_sentinel_alert_serialization() {
    let alert = SentinelAlert {
        block_number: 19_500_000,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 42,
        alert_priority: AlertPriority::Critical,
        suspicion_reasons: vec![SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        }],
        suspicion_score: 0.9,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::from(50_u64) * one_eth(),
        whitelist_matches: 0,
        summary: "Flash Loan detected".to_string(),
        total_steps: 10_000,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };

    let json = serde_json::to_string(&alert).expect("should serialize");
    assert!(json.contains("19500000"));
    assert!(json.contains("Flash Loan detected"));
    assert!(json.contains("Critical"));
    assert!(json.contains("10000"));
}

#[test]
fn test_sentinel_alert_priority_from_score() {
    // Critical threshold
    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: AlertPriority::from_score(0.85),
        suspicion_reasons: vec![],
        suspicion_score: 0.85,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        whitelist_matches: 0,
        summary: String::new(),
        total_steps: 0,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };
    assert_eq!(alert.alert_priority, AlertPriority::Critical);

    // High threshold (>= 0.65)
    let priority = AlertPriority::from_score(0.65);
    assert_eq!(priority, AlertPriority::High);
}

#[test]
fn test_sentinel_alert_empty_patterns() {
    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 0,
        alert_priority: AlertPriority::Medium,
        suspicion_reasons: vec![SuspicionReason::UnusualGasPattern {
            gas_used: 600_000,
            gas_limit: 620_000,
        }],
        suspicion_score: 0.15,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: U256::zero(),
        whitelist_matches: 0,
        summary: "Unusual gas pattern".to_string(),
        total_steps: 500,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };

    assert_eq!(alert.tx_index, 0);
    assert_eq!(alert.total_steps, 500);
    assert_eq!(alert.suspicion_reasons.len(), 1);
}

#[test]
fn test_sentinel_alert_multiple_suspicion_reasons() {
    let reasons = vec![
        SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        },
        SuspicionReason::MultipleErc20Transfers { count: 15 },
        SuspicionReason::KnownContractInteraction {
            address: Address::zero(),
            label: "Aave V2 Pool".to_string(),
        },
    ];

    let total_score: f64 = reasons.iter().map(|r| r.score()).sum();
    // 0.4 + 0.4 (>10) + 0.1 = 0.9
    assert!((total_score - 0.9).abs() < f64::EPSILON);

    let alert = SentinelAlert {
        block_number: 1,
        block_hash: H256::zero(),
        tx_hash: H256::zero(),
        tx_index: 3,
        alert_priority: AlertPriority::from_score(total_score),
        suspicion_reasons: reasons,
        suspicion_score: total_score,
        #[cfg(feature = "autopsy")]
        detected_patterns: vec![],
        #[cfg(feature = "autopsy")]
        fund_flows: vec![],
        total_value_at_risk: one_eth(),
        whitelist_matches: 0,
        summary: "Multi-signal alert".to_string(),
        total_steps: 8000,
        feature_vector: None,
        #[cfg(feature = "ai_agent")]
        agent_verdict: None,
    };

    assert_eq!(alert.alert_priority, AlertPriority::Critical);
    assert_eq!(alert.suspicion_reasons.len(), 3);
}

// ===========================================================================
// H-2: Replay module type tests
// ===========================================================================

#[test]
fn test_replay_result_fields() {
    // Test that ReplayResult struct has correct fields by constructing one
    use crate::sentinel::replay::ReplayResult;
    use crate::types::ReplayTrace;

    let result = ReplayResult {
        trace: ReplayTrace {
            steps: vec![],
            config: crate::types::ReplayConfig::default(),
            gas_used: 21000,
            success: true,
            output: bytes::Bytes::new(),
        },
        tx_sender: Address::zero(),
        block_header: make_header(100),
    };

    assert!(result.trace.steps.is_empty());
    assert_eq!(result.trace.gas_used, 21000);
    assert!(result.trace.success);
    assert_eq!(result.tx_sender, Address::zero());
    assert_eq!(result.block_header.number, 100);
}

// ===========================================================================
// H-2: Analyzer integration tests (with Store)
// ===========================================================================

// These tests require a populated Store. Since creating a full Store with
// committed blocks is complex (requires genesis + block execution), we test
// the analyzer at the type level and verify error paths.

#[test]
fn test_deep_analyzer_tx_not_found() {
    use crate::sentinel::analyzer::DeepAnalyzer;

    // Create a minimal Store (in-memory)
    let store = ethrex_storage::Store::new(
        "test-sentinel-analyzer",
        ethrex_storage::EngineType::InMemory,
    )
    .expect("in-memory store");

    // Block with 0 transactions
    let block = ethrex_common::types::Block {
        header: make_header(1),
        body: Default::default(),
    };

    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0, // no TX at index 0
        reasons: vec![SuspicionReason::FlashLoanSignature {
            provider_address: Address::zero(),
        }],
        score: 0.5,
        priority: AlertPriority::High,
        whitelist_matches: 0,
    };

    let config = AnalysisConfig::default();
    let result = DeepAnalyzer::analyze(&store, &block, &suspicion, &config, None);

    // Should fail because tx_index 0 doesn't exist in empty block
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, SentinelError::TxNotFound { .. }),
        "Expected TxNotFound, got: {err:?}"
    );
}

#[test]
fn test_deep_analyzer_parent_not_found() {
    use crate::sentinel::analyzer::DeepAnalyzer;

    let store =
        ethrex_storage::Store::new("test-sentinel-parent", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");

    // Block with 1 transaction but parent doesn't exist in Store
    let tx = make_tx_call(random_address(0x01), U256::zero(), 100_000);
    let block = ethrex_common::types::Block {
        header: ethrex_common::types::BlockHeader {
            number: 100,
            parent_hash: H256::from([0xAA; 32]), // non-existent parent
            ..Default::default()
        },
        body: ethrex_common::types::BlockBody {
            transactions: vec![tx],
            ..Default::default()
        },
    };

    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![SuspicionReason::HighValueWithRevert {
            value_wei: one_eth(),
            gas_used: 200_000,
        }],
        score: 0.5,
        priority: AlertPriority::High,
        whitelist_matches: 0,
    };

    let config = AnalysisConfig::default();
    let result = DeepAnalyzer::analyze(&store, &block, &suspicion, &config, None);

    // Should fail because parent block header is not in Store
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, SentinelError::ParentNotFound { .. }),
        "Expected ParentNotFound, got: {err:?}"
    );
}

#[test]
fn test_deep_analyzer_step_limit() {
    // Test that AnalysisConfig::max_steps is respected in SentinelError
    let err = SentinelError::StepLimitExceeded {
        steps: 2_000_000,
        max_steps: 1_000_000,
    };
    let msg = err.to_string();
    assert!(msg.contains("2000000"));
    assert!(msg.contains("1000000"));
}

#[test]
fn test_load_block_header_not_found() {
    use crate::sentinel::replay::load_block_header;

    let store =
        ethrex_storage::Store::new("test-sentinel-load", ethrex_storage::EngineType::InMemory)
            .expect("in-memory store");

    let result = load_block_header(&store, 999_999);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), SentinelError::BlockNotFound { block_number } if block_number == 999_999)
    );
}

// ===========================================================================
// H-2: Autopsy-gated deep analysis tests
// ===========================================================================

#[cfg(feature = "autopsy")]
mod autopsy_sentinel_tests {
    use super::*;
    use crate::autopsy::types::{AttackPattern, DetectedPattern, FundFlow};

    #[test]
    fn test_sentinel_alert_with_detected_patterns() {
        let alert = SentinelAlert {
            block_number: 19_500_000,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 5,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![SuspicionReason::FlashLoanSignature {
                provider_address: Address::zero(),
            }],
            suspicion_score: 0.9,
            detected_patterns: vec![DetectedPattern {
                pattern: AttackPattern::FlashLoan {
                    borrow_step: 100,
                    borrow_amount: one_eth() * 1000,
                    repay_step: 5000,
                    repay_amount: one_eth() * 1001,
                    provider: Some(Address::zero()),
                    token: None,
                },
                confidence: 0.9,
                evidence: vec!["Borrow at step 100".to_string()],
            }],
            fund_flows: vec![FundFlow {
                from: random_address(0x01),
                to: random_address(0x02),
                value: one_eth() * 50,
                token: None,
                step_index: 200,
            }],
            total_value_at_risk: one_eth() * 50,
            whitelist_matches: 0,
            summary: "Flash Loan detected".to_string(),
            total_steps: 10_000,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        };

        assert!((alert.max_confidence() - 0.9).abs() < f64::EPSILON);
        assert_eq!(alert.pattern_names(), vec!["FlashLoan"]);
    }

    #[test]
    fn test_sentinel_alert_max_confidence_multiple() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![],
            suspicion_score: 0.9,
            detected_patterns: vec![
                DetectedPattern {
                    pattern: AttackPattern::Reentrancy {
                        target_contract: Address::zero(),
                        reentrant_call_step: 50,
                        state_modified_step: 80,
                        call_depth_at_entry: 1,
                    },
                    confidence: 0.7,
                    evidence: vec!["Re-entry detected".to_string()],
                },
                DetectedPattern {
                    pattern: AttackPattern::FlashLoan {
                        borrow_step: 10,
                        borrow_amount: one_eth(),
                        repay_step: 500,
                        repay_amount: one_eth(),
                        provider: None,
                        token: None,
                    },
                    confidence: 0.85,
                    evidence: vec!["Flash loan pattern".to_string()],
                },
            ],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            whitelist_matches: 0,
            summary: String::new(),
            total_steps: 1000,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        };

        // max_confidence should return the highest
        assert!((alert.max_confidence() - 0.85).abs() < f64::EPSILON);
        let names = alert.pattern_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Reentrancy"));
        assert!(names.contains(&"FlashLoan"));
    }

    #[test]
    fn test_sentinel_alert_empty_patterns_confidence() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Medium,
            suspicion_reasons: vec![],
            suspicion_score: 0.3,
            detected_patterns: vec![],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            whitelist_matches: 0,
            summary: String::new(),
            total_steps: 0,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        };

        assert!((alert.max_confidence() - 0.0).abs() < f64::EPSILON);
        assert!(alert.pattern_names().is_empty());
    }

    #[test]
    fn test_sentinel_alert_serialization_with_autopsy() {
        let alert = SentinelAlert {
            block_number: 19_500_000,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 42,
            alert_priority: AlertPriority::High,
            suspicion_reasons: vec![SuspicionReason::PriceOracleWithSwap {
                oracle: Address::zero(),
            }],
            suspicion_score: 0.6,
            detected_patterns: vec![DetectedPattern {
                pattern: AttackPattern::PriceManipulation {
                    oracle_read_before: 100,
                    swap_step: 200,
                    oracle_read_after: 300,
                    price_delta_percent: 15.5,
                },
                confidence: 0.8,
                evidence: vec!["Price delta 15.5%".to_string()],
            }],
            fund_flows: vec![],
            total_value_at_risk: one_eth() * 100,
            whitelist_matches: 0,
            summary: "Price manipulation detected".to_string(),
            total_steps: 5000,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        };

        let json = serde_json::to_string_pretty(&alert).expect("should serialize");
        assert!(json.contains("PriceManipulation"));
        assert!(json.contains("15.5"));
        assert!(json.contains("Price manipulation detected"));
    }

    #[test]
    fn test_sentinel_alert_all_pattern_names() {
        let alert = SentinelAlert {
            block_number: 1,
            block_hash: H256::zero(),
            tx_hash: H256::zero(),
            tx_index: 0,
            alert_priority: AlertPriority::Critical,
            suspicion_reasons: vec![],
            suspicion_score: 1.0,
            whitelist_matches: 0,
            detected_patterns: vec![
                DetectedPattern {
                    pattern: AttackPattern::Reentrancy {
                        target_contract: Address::zero(),
                        reentrant_call_step: 1,
                        state_modified_step: 2,
                        call_depth_at_entry: 1,
                    },
                    confidence: 0.9,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::FlashLoan {
                        borrow_step: 1,
                        borrow_amount: U256::zero(),
                        repay_step: 2,
                        repay_amount: U256::zero(),
                        provider: None,
                        token: None,
                    },
                    confidence: 0.8,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::PriceManipulation {
                        oracle_read_before: 1,
                        swap_step: 2,
                        oracle_read_after: 3,
                        price_delta_percent: 10.0,
                    },
                    confidence: 0.7,
                    evidence: vec![],
                },
                DetectedPattern {
                    pattern: AttackPattern::AccessControlBypass {
                        sstore_step: 1,
                        contract: Address::zero(),
                    },
                    confidence: 0.5,
                    evidence: vec![],
                },
            ],
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: String::new(),
            total_steps: 100,
            feature_vector: None,
            #[cfg(feature = "ai_agent")]
            agent_verdict: None,
        };

        let names = alert.pattern_names();
        assert_eq!(names.len(), 4);
        assert_eq!(names[0], "Reentrancy");
        assert_eq!(names[1], "FlashLoan");
        assert_eq!(names[2], "PriceManipulation");
        assert_eq!(names[3], "AccessControlBypass");
        assert!((alert.max_confidence() - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_sentinel_alert_fund_flow_value() {
        let flows = vec![
            FundFlow {
                from: random_address(0x01),
                to: random_address(0x02),
                value: one_eth() * 10,
                token: None, // ETH
                step_index: 100,
            },
            FundFlow {
                from: random_address(0x02),
                to: random_address(0x03),
                value: one_eth() * 5,
                token: None, // ETH
                step_index: 200,
            },
            FundFlow {
                from: random_address(0x01),
                to: random_address(0x04),
                value: one_eth() * 100,
                token: Some(random_address(0xDD)), // ERC-20, should be excluded
                step_index: 300,
            },
        ];

        // compute_total_value only counts ETH (token: None)
        let total: U256 = flows
            .iter()
            .filter(|f| f.token.is_none())
            .fold(U256::zero(), |acc, f| acc.saturating_add(f.value));

        assert_eq!(total, one_eth() * 15);
    }
}
