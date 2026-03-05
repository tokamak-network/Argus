//! Systematic replay benchmark for exploit detection pipeline.
//!
//! Runs all exploit fixtures through the full detection stack (classifier,
//! fund flow tracer, feature extraction, confidence scoring) and reports:
//! - Detection rate: how many known attacks are correctly classified
//! - Classification accuracy: correct attack type identified
//! - Confidence levels: per-fixture confidence scores
//! - Per-stage timing: classifier, fund flow, feature extraction (μs)
//!
//! All fixtures are synthetic — no network access required.

use std::time::Instant;

use crate::autopsy::classifier::AttackClassifier;
use crate::autopsy::fund_flow::FundFlowTracer;
use crate::autopsy::types::AttackPattern;
use crate::sentinel::pipeline::FeatureVector;
use crate::types::StepRecord;

use super::exploit_fixtures;

// ── Fixture registry ─────────────────────────────────────────────

/// Expected attack type for each fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedAttack {
    Reentrancy,
    FlashLoan,
    PriceManipulation,
    AccessControlBypass,
}

impl std::fmt::Display for ExpectedAttack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reentrancy => write!(f, "Reentrancy"),
            Self::FlashLoan => write!(f, "FlashLoan"),
            Self::PriceManipulation => write!(f, "PriceManipulation"),
            Self::AccessControlBypass => write!(f, "AccessControlBypass"),
        }
    }
}

fn matches_expected(pattern: &AttackPattern, expected: ExpectedAttack) -> bool {
    match (pattern, expected) {
        (AttackPattern::Reentrancy { .. }, ExpectedAttack::Reentrancy) => true,
        (AttackPattern::FlashLoan { .. }, ExpectedAttack::FlashLoan) => true,
        (AttackPattern::PriceManipulation { .. }, ExpectedAttack::PriceManipulation) => true,
        (AttackPattern::AccessControlBypass { .. }, ExpectedAttack::AccessControlBypass) => true,
        _ => false,
    }
}

struct FixtureSpec {
    name: &'static str,
    /// Real-world exploit this fixture models.
    modeled_after: &'static str,
    /// Function to generate the trace.
    build: fn() -> Vec<StepRecord>,
    /// Expected primary attack type.
    expected: ExpectedAttack,
    /// Minimum acceptable confidence (0.0-1.0).
    min_confidence: f64,
}

fn fixture_registry() -> Vec<FixtureSpec> {
    vec![
        FixtureSpec {
            name: "reentrancy_dao",
            modeled_after: "The DAO (2016)",
            build: exploit_fixtures::reentrancy_dao_fixture,
            expected: ExpectedAttack::Reentrancy,
            min_confidence: 0.7,
        },
        FixtureSpec {
            name: "flash_loan_euler",
            modeled_after: "Euler Finance (2023)",
            build: exploit_fixtures::flash_loan_euler_fixture,
            expected: ExpectedAttack::FlashLoan,
            min_confidence: 0.5,
        },
        FixtureSpec {
            name: "price_manipulation_balancer",
            modeled_after: "Balancer V2 (2023)",
            build: exploit_fixtures::price_manipulation_balancer_fixture,
            expected: ExpectedAttack::PriceManipulation,
            min_confidence: 0.5,
        },
        FixtureSpec {
            name: "access_control_bybit",
            modeled_after: "Bybit (2025)",
            build: exploit_fixtures::access_control_bybit_fixture,
            expected: ExpectedAttack::AccessControlBypass,
            min_confidence: 0.5,
        },
        FixtureSpec {
            name: "access_control_poly_network",
            modeled_after: "Poly Network (2021)",
            build: exploit_fixtures::access_control_poly_network_fixture,
            expected: ExpectedAttack::AccessControlBypass,
            min_confidence: 0.5,
        },
    ]
}

// ── Per-fixture result ───────────────────────────────────────────

#[derive(Debug)]
struct FixtureResult {
    name: &'static str,
    modeled_after: &'static str,
    step_count: usize,
    // Detection
    detected: bool,
    correct_type: bool,
    confidence: f64,
    all_patterns: Vec<String>,
    // Fund flow
    eth_flows: usize,
    erc20_flows: usize,
    // Features
    reentrancy_depth: f64,
    max_call_depth: f64,
    anomaly_score: f64,
    // Timing (microseconds)
    classifier_us: u64,
    fund_flow_us: u64,
    feature_us: u64,
    total_us: u64,
}

// ── Benchmark runner ─────────────────────────────────────────────

fn run_single_fixture(spec: &FixtureSpec) -> FixtureResult {
    let steps = (spec.build)();
    let step_count = steps.len();
    let total_start = Instant::now();

    // Stage 1: Classifier
    let classify_start = Instant::now();
    let detected = AttackClassifier::classify_with_confidence(&steps);
    let classifier_us = classify_start.elapsed().as_micros() as u64;

    // Stage 2: Fund flow
    let flow_start = Instant::now();
    let flows = FundFlowTracer::trace(&steps);
    let fund_flow_us = flow_start.elapsed().as_micros() as u64;

    // Stage 3: Feature extraction
    let feature_start = Instant::now();
    let features = FeatureVector::from_trace(&steps, 500_000, 30_000_000);
    let feature_us = feature_start.elapsed().as_micros() as u64;

    let total_us = total_start.elapsed().as_micros() as u64;

    // Anomaly score (using default statistical model)
    let model = crate::sentinel::ml_model::StatisticalAnomalyDetector::default();
    let anomaly_score = crate::sentinel::ml_model::AnomalyModel::predict(&model, &features);

    // Check detection
    let primary_match = detected
        .iter()
        .find(|d| matches_expected(&d.pattern, spec.expected));
    let detected_flag = primary_match.is_some();
    let confidence = primary_match.map(|d| d.confidence).unwrap_or(0.0);

    let all_patterns: Vec<String> = detected
        .iter()
        .map(|d| {
            format!(
                "{} ({:.0}%)",
                pattern_name(&d.pattern),
                d.confidence * 100.0
            )
        })
        .collect();

    let eth_flows = flows.iter().filter(|f| f.token.is_none()).count();
    let erc20_flows = flows.iter().filter(|f| f.token.is_some()).count();

    FixtureResult {
        name: spec.name,
        modeled_after: spec.modeled_after,
        step_count,
        detected: detected_flag,
        correct_type: detected_flag,
        confidence,
        all_patterns,
        eth_flows,
        erc20_flows,
        reentrancy_depth: features.reentrancy_depth,
        max_call_depth: features.max_call_depth,
        anomaly_score,
        classifier_us,
        fund_flow_us,
        feature_us,
        total_us,
    }
}

fn pattern_name(p: &AttackPattern) -> &'static str {
    match p {
        AttackPattern::Reentrancy { .. } => "Reentrancy",
        AttackPattern::FlashLoan { .. } => "FlashLoan",
        AttackPattern::PriceManipulation { .. } => "PriceManipulation",
        AttackPattern::AccessControlBypass { .. } => "AccessControlBypass",
    }
}

// ── Report rendering ─────────────────────────────────────────────

fn render_report(results: &[FixtureResult]) -> String {
    let total = results.len();
    let detected_count = results.iter().filter(|r| r.detected).count();
    let correct_count = results.iter().filter(|r| r.correct_type).count();

    let mut out = String::new();
    out.push_str("\n");
    out.push_str("╔══════════════════════════════════════════════════════════════════════════╗\n");
    out.push_str("║             Argus Exploit Detection Benchmark Report                    ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════════════════╝\n");
    out.push_str("\n");

    // Summary
    out.push_str(&format!(
        "Detection Rate:         {}/{} ({:.0}%)\n",
        detected_count,
        total,
        detected_count as f64 / total as f64 * 100.0
    ));
    out.push_str(&format!(
        "Classification Accuracy: {}/{} ({:.0}%)\n",
        correct_count,
        total,
        correct_count as f64 / total as f64 * 100.0
    ));

    let avg_confidence: f64 = if detected_count > 0 {
        results
            .iter()
            .filter(|r| r.detected)
            .map(|r| r.confidence)
            .sum::<f64>()
            / detected_count as f64
    } else {
        0.0
    };
    out.push_str(&format!(
        "Average Confidence:      {:.1}%\n",
        avg_confidence * 100.0
    ));

    let total_time_us: u64 = results.iter().map(|r| r.total_us).sum();
    out.push_str(&format!("Total Pipeline Time:     {} us\n", total_time_us));
    out.push_str("\n");

    // Per-fixture table
    out.push_str(
        "┌─────────────────────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐\n",
    );
    out.push_str(
        "│ Fixture                     │ Detected │ Correct  │ Confid.  │ Steps    │ Time(us) │\n",
    );
    out.push_str(
        "├─────────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤\n",
    );

    for r in results {
        out.push_str(&format!(
            "│ {:<27} │ {:<8} │ {:<8} │ {:>5.1}%   │ {:>8} │ {:>8} │\n",
            r.name,
            if r.detected { "YES" } else { "NO" },
            if r.correct_type { "YES" } else { "NO" },
            r.confidence * 100.0,
            r.step_count,
            r.total_us,
        ));
    }

    out.push_str(
        "└─────────────────────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘\n",
    );
    out.push_str("\n");

    // Per-fixture detail
    out.push_str("── Detailed Results ──────────────────────────────────────────────────────\n\n");

    for r in results {
        out.push_str(&format!(
            "  {} (modeled after: {})\n",
            r.name, r.modeled_after
        ));
        out.push_str(&format!(
            "    Patterns: {}\n",
            if r.all_patterns.is_empty() {
                "NONE".to_string()
            } else {
                r.all_patterns.join(", ")
            }
        ));
        out.push_str(&format!(
            "    Fund flows: {} ETH, {} ERC-20\n",
            r.eth_flows, r.erc20_flows
        ));
        out.push_str(&format!(
            "    Features: reentrancy_depth={:.0}, max_call_depth={:.0}, anomaly={:.4}\n",
            r.reentrancy_depth, r.max_call_depth, r.anomaly_score
        ));
        out.push_str(&format!(
            "    Timing: classifier={}us, fund_flow={}us, features={}us\n",
            r.classifier_us, r.fund_flow_us, r.feature_us
        ));
        out.push_str("\n");
    }

    out
}

// ── JSON output ──────────────────────────────────────────────────

fn results_to_json(results: &[FixtureResult]) -> serde_json::Value {
    let total = results.len();
    let detected_count = results.iter().filter(|r| r.detected).count();
    let correct_count = results.iter().filter(|r| r.correct_type).count();

    serde_json::json!({
        "summary": {
            "total_fixtures": total,
            "detected": detected_count,
            "correct_type": correct_count,
            "detection_rate": format!("{:.1}%", detected_count as f64 / total as f64 * 100.0),
            "classification_accuracy": format!("{:.1}%", correct_count as f64 / total as f64 * 100.0),
        },
        "fixtures": results.iter().map(|r| {
            serde_json::json!({
                "name": r.name,
                "modeled_after": r.modeled_after,
                "step_count": r.step_count,
                "detected": r.detected,
                "correct_type": r.correct_type,
                "confidence": r.confidence,
                "patterns": r.all_patterns,
                "eth_flows": r.eth_flows,
                "erc20_flows": r.erc20_flows,
                "features": {
                    "reentrancy_depth": r.reentrancy_depth,
                    "max_call_depth": r.max_call_depth,
                    "anomaly_score": r.anomaly_score,
                },
                "timing_us": {
                    "classifier": r.classifier_us,
                    "fund_flow": r.fund_flow_us,
                    "feature_extraction": r.feature_us,
                    "total": r.total_us,
                },
            })
        }).collect::<Vec<_>>(),
    })
}

// ── Tests ────────────────────────────────────────────────────────

/// Full benchmark: runs all fixtures and prints a formatted report.
#[test]
fn benchmark_all_exploit_fixtures() {
    let registry = fixture_registry();
    let results: Vec<FixtureResult> = registry.iter().map(run_single_fixture).collect();

    let report = render_report(&results);
    println!("{report}");

    let json = results_to_json(&results);
    println!(
        "--- JSON ---\n{}\n",
        serde_json::to_string_pretty(&json).unwrap()
    );

    // Aggregate assertions
    let total = results.len();
    let detected_count = results.iter().filter(|r| r.detected).count();
    let detection_rate = detected_count as f64 / total as f64;

    assert!(
        detection_rate >= 0.8,
        "Detection rate {:.0}% below 80% threshold ({}/{})",
        detection_rate * 100.0,
        detected_count,
        total,
    );
}

/// Each fixture must detect the expected attack type.
#[test]
fn each_fixture_detects_expected_pattern() {
    for spec in &fixture_registry() {
        let steps = (spec.build)();
        let detected = AttackClassifier::classify_with_confidence(&steps);

        let found = detected
            .iter()
            .any(|d| matches_expected(&d.pattern, spec.expected));

        assert!(
            found,
            "Fixture '{}' (modeled after {}) should detect {:?}. Got: {:?}",
            spec.name,
            spec.modeled_after,
            spec.expected,
            detected
                .iter()
                .map(|d| pattern_name(&d.pattern))
                .collect::<Vec<_>>(),
        );
    }
}

/// Each fixture must meet its minimum confidence threshold.
#[test]
fn each_fixture_meets_confidence_threshold() {
    for spec in &fixture_registry() {
        let steps = (spec.build)();
        let detected = AttackClassifier::classify_with_confidence(&steps);

        let primary = detected
            .iter()
            .find(|d| matches_expected(&d.pattern, spec.expected));

        let d = primary.unwrap_or_else(|| {
            panic!(
                "Fixture '{}': expected pattern {:?} not detected",
                spec.name, spec.expected,
            )
        });
        assert!(
            d.confidence >= spec.min_confidence,
            "Fixture '{}': confidence {:.2} below minimum {:.2}",
            spec.name,
            d.confidence,
            spec.min_confidence,
        );
    }
}

/// Feature extraction produces sane values for all fixtures.
#[test]
fn feature_extraction_sanity_check() {
    for spec in &fixture_registry() {
        let steps = (spec.build)();
        let features = FeatureVector::from_trace(&steps, 500_000, 30_000_000);

        assert!(
            features.total_steps > 0.0,
            "Fixture '{}': total_steps should be > 0",
            spec.name,
        );
        assert!(
            features.unique_addresses > 0.0,
            "Fixture '{}': unique_addresses should be > 0",
            spec.name,
        );
        assert!(
            features.gas_ratio > 0.0 && features.gas_ratio <= 1.0,
            "Fixture '{}': gas_ratio should be in (0, 1], got {}",
            spec.name,
            features.gas_ratio,
        );
    }
}

/// Fund flow tracer extracts at least one flow for attack fixtures with value transfers.
#[test]
fn fund_flow_extraction_for_attacks() {
    // DAO reentrancy has ETH transfers
    let steps = exploit_fixtures::reentrancy_dao_fixture();
    let flows = FundFlowTracer::trace(&steps);
    let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
    assert!(
        !eth_flows.is_empty(),
        "DAO reentrancy should have ETH fund flows",
    );

    // Euler flash loan has ERC-20 transfers
    let steps = exploit_fixtures::flash_loan_euler_fixture();
    let flows = FundFlowTracer::trace(&steps);
    let erc20_flows: Vec<_> = flows.iter().filter(|f| f.token.is_some()).collect();
    assert!(
        !erc20_flows.is_empty(),
        "Euler flash loan should have ERC-20 fund flows",
    );
}

/// Pipeline timing: no single fixture should take more than 10ms (100 steps ~ μs range).
#[test]
fn pipeline_timing_under_threshold() {
    let max_us = 10_000; // 10ms — generous for synthetic fixtures
    for spec in &fixture_registry() {
        let result = run_single_fixture(spec);
        assert!(
            result.total_us < max_us,
            "Fixture '{}': pipeline took {}us, exceeds {}us threshold",
            spec.name,
            result.total_us,
            max_us,
        );
    }
}
