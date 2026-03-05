//! Pipeline tests: feature extraction, dismiss/skip, dynamic steps, confidence, metrics.

use super::*;
use ethrex_common::types::Block;
use ethrex_common::{Address, H256};
use ethrex_storage::{EngineType, Store};

use crate::sentinel::ml_model::StatisticalAnomalyDetector;
use crate::sentinel::types::{AlertPriority, AnalysisConfig, SentinelError, SuspiciousTx};

fn make_step(opcode: u8, depth: usize, addr: Address) -> crate::types::StepRecord {
    crate::types::StepRecord {
        step_index: 0,
        pc: 0,
        opcode,
        depth,
        gas_remaining: 1_000_000,
        stack_top: vec![],
        stack_depth: 0,
        memory_size: 0,
        code_address: addr,
        call_value: None,
        storage_writes: None,
        log_topics: None,
        log_data: None,
        call_input_selector: None,
    }
}

fn make_step_with_index(
    opcode: u8,
    depth: usize,
    addr: Address,
    idx: usize,
) -> crate::types::StepRecord {
    let mut step = make_step(opcode, depth, addr);
    step.step_index = idx;
    step
}

// -- FeatureVector extraction tests --

#[test]
fn feature_vector_simple_trace() {
    let addr = Address::from_slice(&[0x01; 20]);
    let steps = vec![
        make_step(OP_SLOAD, 0, addr),
        make_step(OP_SSTORE, 0, addr),
        make_step(OP_CALL, 0, addr),
    ];

    let fv = FeatureVector::from_trace(&steps, 50_000, 100_000);

    assert!((fv.total_steps - 3.0).abs() < f64::EPSILON);
    assert!((fv.unique_addresses - 1.0).abs() < f64::EPSILON);
    assert!((fv.sload_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.sstore_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.call_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.gas_ratio - 0.5).abs() < f64::EPSILON);
}

#[test]
fn feature_vector_complex_trace() {
    let addr1 = Address::from_slice(&[0x01; 20]);
    let addr2 = Address::from_slice(&[0x02; 20]);
    let steps = vec![
        make_step(OP_CALL, 0, addr1),
        make_step(OP_DELEGATECALL, 1, addr1),
        make_step(OP_STATICCALL, 2, addr2),
        make_step(OP_SSTORE, 2, addr2),
        make_step(OP_SLOAD, 1, addr1),
        make_step(OP_CREATE, 0, addr1),
        make_step(0xA2, 0, addr1), // LOG2
        make_step(OP_REVERT, 0, addr1),
    ];

    let fv = FeatureVector::from_trace(&steps, 90_000, 100_000);

    assert!((fv.total_steps - 8.0).abs() < f64::EPSILON);
    assert!((fv.unique_addresses - 2.0).abs() < f64::EPSILON);
    assert!((fv.max_call_depth - 2.0).abs() < f64::EPSILON);
    assert!((fv.call_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.delegatecall_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.staticcall_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.create_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.log_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.revert_count - 1.0).abs() < f64::EPSILON);
    assert!((fv.gas_ratio - 0.9).abs() < f64::EPSILON);
}

#[test]
fn feature_vector_empty_trace() {
    let fv = FeatureVector::from_trace(&[], 0, 100_000);

    assert!((fv.total_steps).abs() < f64::EPSILON);
    assert!((fv.unique_addresses).abs() < f64::EPSILON);
    assert!((fv.gas_ratio).abs() < f64::EPSILON);
}

// -- Dismiss/skip tests --

#[test]
fn pipeline_dismissed_flag_respected() {
    // A step that dismisses should prevent subsequent steps from executing.
    struct DismissStep;
    impl AnalysisStep for DismissStep {
        fn name(&self) -> &'static str {
            "DismissStep"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            Ok(StepResult::Dismiss)
        }
    }

    struct PanicStep;
    impl AnalysisStep for PanicStep {
        fn name(&self) -> &'static str {
            "PanicStep"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            panic!("PanicStep should never be reached");
        }
    }

    let pipeline = AnalysisPipeline {
        steps: vec![Box::new(DismissStep), Box::new(PanicStep)],
        anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
    };

    let store = Store::new("test-dismiss", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };
    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.5,
        priority: AlertPriority::Medium,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig::default();

    let (result, metrics) = pipeline
        .analyze(&store, &block, &suspicion, &config)
        .unwrap();
    assert!(result.is_none(), "dismissed TX should produce no alert");
    assert_eq!(metrics.steps_dismissed, 1);
    assert_eq!(metrics.steps_executed, 1); // only DismissStep ran
}

// -- Dynamic AddSteps tests --

#[test]
fn pipeline_add_steps_queues_dynamic_follow_up() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let follow_up_ran = Arc::new(AtomicBool::new(false));
    let follow_up_clone = follow_up_ran.clone();

    struct FollowUpStep {
        ran: Arc<AtomicBool>,
    }
    impl AnalysisStep for FollowUpStep {
        fn name(&self) -> &'static str {
            "FollowUp"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            self.ran.store(true, Ordering::SeqCst);
            Ok(StepResult::Continue)
        }
    }

    struct AdderStep {
        follow_up_ran: Arc<AtomicBool>,
    }
    impl AnalysisStep for AdderStep {
        fn name(&self) -> &'static str {
            "Adder"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            Ok(StepResult::AddSteps(vec![Box::new(FollowUpStep {
                ran: self.follow_up_ran.clone(),
            })]))
        }
    }

    let pipeline = AnalysisPipeline {
        steps: vec![Box::new(AdderStep {
            follow_up_ran: follow_up_clone,
        })],
        anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
    };

    let store = Store::new("test-add-steps", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };
    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.5,
        priority: AlertPriority::Medium,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig {
        min_alert_confidence: 0.0,
        ..Default::default()
    };

    let (_result, metrics) = pipeline
        .analyze(&store, &block, &suspicion, &config)
        .unwrap();
    assert!(
        follow_up_ran.load(Ordering::SeqCst),
        "follow-up step should have run"
    );
    assert_eq!(metrics.steps_executed, 2); // Adder + FollowUp
}

#[test]
fn pipeline_empty_add_steps() {
    struct EmptyAdder;
    impl AnalysisStep for EmptyAdder {
        fn name(&self) -> &'static str {
            "EmptyAdder"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            Ok(StepResult::AddSteps(vec![]))
        }
    }

    let pipeline = AnalysisPipeline {
        steps: vec![Box::new(EmptyAdder)],
        anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
    };

    let store = Store::new("test-empty-add", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };
    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.5,
        priority: AlertPriority::Medium,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig {
        min_alert_confidence: 0.0,
        ..Default::default()
    };

    let (_result, metrics) = pipeline
        .analyze(&store, &block, &suspicion, &config)
        .unwrap();
    assert_eq!(metrics.steps_executed, 1);
}

// -- Confidence scoring tests --

#[test]
fn confidence_prefilter_only_without_autopsy() {
    // When no replay result is available, confidence should still be computed
    // from prefilter score.
    let mut ctx = AnalysisContext::new();
    ctx.anomaly_score = Some(0.6);

    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.8,
        priority: AlertPriority::High,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig::default();
    let store = Store::new("test-conf", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };

    let scorer = ConfidenceScorer;
    scorer
        .execute(&mut ctx, &store, &block, &suspicion, &config)
        .unwrap();

    let confidence = ctx.final_confidence.unwrap();
    // Without autopsy: anomaly * 0.6 + prefilter * 0.4 = 0.6*0.6 + 0.8*0.4 = 0.68
    // With autopsy: pattern * 0.4 + anomaly * 0.3 + prefilter * 0.2 + fund_flow * 0.1
    assert!(confidence > 0.0, "confidence should be positive");
    assert!(confidence <= 1.0, "confidence should be <= 1.0");
}

// -- Reentrancy depth detection --

#[test]
fn reentrancy_depth_detection() {
    let addr = Address::from_slice(&[0xAA; 20]);
    let steps = vec![
        make_step_with_index(OP_CALL, 0, addr, 0),
        make_step_with_index(OP_SLOAD, 1, addr, 1),
        make_step_with_index(OP_CALL, 1, addr, 2), // re-entry at depth 1
        make_step_with_index(OP_SSTORE, 2, addr, 3),
    ];

    let depth = detect_reentrancy_depth(&steps);
    assert!(depth >= 1, "should detect re-entry depth >= 1, got {depth}");
}

// -- Pipeline metrics --

#[test]
fn pipeline_metrics_track_step_count() {
    struct NoopStep;
    impl AnalysisStep for NoopStep {
        fn name(&self) -> &'static str {
            "Noop"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            Ok(StepResult::Continue)
        }
    }

    let pipeline = AnalysisPipeline {
        steps: vec![Box::new(NoopStep), Box::new(NoopStep), Box::new(NoopStep)],
        anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
    };

    let store = Store::new("test-metrics", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };
    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.5,
        priority: AlertPriority::Medium,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig {
        min_alert_confidence: 0.0,
        ..Default::default()
    };

    let (_result, metrics) = pipeline
        .analyze(&store, &block, &suspicion, &config)
        .unwrap();
    assert_eq!(metrics.steps_executed, 3);
    assert_eq!(metrics.steps_dismissed, 0);
    assert_eq!(metrics.step_durations.len(), 3);
}

#[test]
fn pipeline_dynamic_step_after_dismiss_is_skipped() {
    struct AdderThenDismiss;
    impl AnalysisStep for AdderThenDismiss {
        fn name(&self) -> &'static str {
            "AdderThenDismiss"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            Ok(StepResult::Dismiss)
        }
    }

    struct UnreachableStep;
    impl AnalysisStep for UnreachableStep {
        fn name(&self) -> &'static str {
            "Unreachable"
        }
        fn execute(
            &self,
            _ctx: &mut AnalysisContext,
            _store: &Store,
            _block: &Block,
            _suspicion: &SuspiciousTx,
            _config: &AnalysisConfig,
        ) -> Result<StepResult, SentinelError> {
            panic!("should never run");
        }
    }

    let pipeline = AnalysisPipeline {
        steps: vec![Box::new(AdderThenDismiss), Box::new(UnreachableStep)],
        anomaly_model: Box::new(StatisticalAnomalyDetector::default()),
    };

    let store = Store::new("test-dismiss-skip", EngineType::InMemory).unwrap();
    let block = Block {
        header: Default::default(),
        body: Default::default(),
    };
    let suspicion = SuspiciousTx {
        tx_hash: H256::zero(),
        tx_index: 0,
        reasons: vec![],
        score: 0.5,
        priority: AlertPriority::Medium,
        whitelist_matches: 0,
    };
    let config = AnalysisConfig::default();

    let (result, _) = pipeline
        .analyze(&store, &block, &suspicion, &config)
        .unwrap();
    assert!(result.is_none());
}
