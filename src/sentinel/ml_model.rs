//! Statistical anomaly detection for the sentinel pipeline.
//!
//! Provides a trait-based anomaly scoring interface and a concrete
//! `StatisticalAnomalyDetector` that uses z-scores mapped through a sigmoid
//! to produce a 0.0 (benign) to 1.0 (malicious) anomaly score.

use super::pipeline::FeatureVector;

/// Traceability: placeholder means/stddevs were calibrated against
/// mainnet blocks 18_000_000..19_000_000 (approximate normal TX profile).
pub const CALIBRATION_BLOCK_RANGE: (u64, u64) = (18_000_000, 19_000_000);

/// Anomaly scoring model that maps a `FeatureVector` to a suspicion score.
pub trait AnomalyModel: Send + Sync {
    /// Predict how anomalous the given features are.
    /// Returns a value in [0.0, 1.0] where 0.0 = benign and 1.0 = malicious.
    fn predict(&self, features: &FeatureVector) -> f64;
}

/// Z-score based anomaly detector with sigmoid mapping.
///
/// For each feature dimension, computes `|value - mean| / stddev` (z-score).
/// The average z-score across all dimensions is mapped through a sigmoid
/// `1 / (1 + exp(-z))` to produce a bounded [0.0, 1.0] anomaly score.
pub struct StatisticalAnomalyDetector {
    means: FeatureVector,
    stddevs: FeatureVector,
}

impl StatisticalAnomalyDetector {
    /// Create a detector with custom means and standard deviations.
    pub fn new(means: FeatureVector, stddevs: FeatureVector) -> Self {
        Self { means, stddevs }
    }

    /// Compute the z-score for a single dimension.
    /// Returns 0.0 if stddev is zero (no variance).
    fn zscore(value: f64, mean: f64, stddev: f64) -> f64 {
        if stddev <= f64::EPSILON {
            return 0.0;
        }
        ((value - mean) / stddev).abs()
    }
}

impl Default for StatisticalAnomalyDetector {
    /// Conservative placeholder values derived from typical mainnet TX profiles.
    /// High stddevs keep sensitivity low until real calibration data is available.
    fn default() -> Self {
        Self {
            means: FeatureVector {
                total_steps: 200.0,
                unique_addresses: 3.0,
                max_call_depth: 2.0,
                sstore_count: 2.0,
                sload_count: 5.0,
                call_count: 2.0,
                delegatecall_count: 0.5,
                staticcall_count: 1.0,
                create_count: 0.1,
                selfdestruct_count: 0.0,
                log_count: 1.0,
                revert_count: 0.1,
                reentrancy_depth: 0.0,
                eth_transferred_wei: 0.0,
                gas_ratio: 0.5,
                calldata_entropy: 4.0,
            },
            stddevs: FeatureVector {
                total_steps: 500.0,
                unique_addresses: 5.0,
                max_call_depth: 3.0,
                sstore_count: 5.0,
                sload_count: 10.0,
                call_count: 5.0,
                delegatecall_count: 2.0,
                staticcall_count: 3.0,
                create_count: 1.0,
                selfdestruct_count: 0.5,
                log_count: 3.0,
                revert_count: 1.0,
                reentrancy_depth: 1.0,
                eth_transferred_wei: 1e18,
                gas_ratio: 0.3,
                calldata_entropy: 2.0,
            },
        }
    }
}

impl AnomalyModel for StatisticalAnomalyDetector {
    fn predict(&self, features: &FeatureVector) -> f64 {
        let zscores = [
            Self::zscore(features.total_steps, self.means.total_steps, self.stddevs.total_steps),
            Self::zscore(
                features.unique_addresses,
                self.means.unique_addresses,
                self.stddevs.unique_addresses,
            ),
            Self::zscore(
                features.max_call_depth,
                self.means.max_call_depth,
                self.stddevs.max_call_depth,
            ),
            Self::zscore(
                features.sstore_count,
                self.means.sstore_count,
                self.stddevs.sstore_count,
            ),
            Self::zscore(features.sload_count, self.means.sload_count, self.stddevs.sload_count),
            Self::zscore(features.call_count, self.means.call_count, self.stddevs.call_count),
            Self::zscore(
                features.delegatecall_count,
                self.means.delegatecall_count,
                self.stddevs.delegatecall_count,
            ),
            Self::zscore(
                features.staticcall_count,
                self.means.staticcall_count,
                self.stddevs.staticcall_count,
            ),
            Self::zscore(
                features.create_count,
                self.means.create_count,
                self.stddevs.create_count,
            ),
            Self::zscore(
                features.selfdestruct_count,
                self.means.selfdestruct_count,
                self.stddevs.selfdestruct_count,
            ),
            Self::zscore(features.log_count, self.means.log_count, self.stddevs.log_count),
            Self::zscore(
                features.revert_count,
                self.means.revert_count,
                self.stddevs.revert_count,
            ),
            Self::zscore(
                features.reentrancy_depth,
                self.means.reentrancy_depth,
                self.stddevs.reentrancy_depth,
            ),
            Self::zscore(
                features.eth_transferred_wei,
                self.means.eth_transferred_wei,
                self.stddevs.eth_transferred_wei,
            ),
            Self::zscore(features.gas_ratio, self.means.gas_ratio, self.stddevs.gas_ratio),
            Self::zscore(
                features.calldata_entropy,
                self.means.calldata_entropy,
                self.stddevs.calldata_entropy,
            ),
        ];

        let n = zscores.len() as f64;
        let avg_zscore: f64 = zscores.iter().sum::<f64>() / n;

        // Sigmoid mapping: 1 / (1 + exp(-z))
        1.0 / (1.0 + (-avg_zscore).exp())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_benign_features_low_score() {
        let detector = StatisticalAnomalyDetector::default();
        let features = FeatureVector {
            total_steps: 150.0,
            unique_addresses: 2.0,
            max_call_depth: 1.0,
            sstore_count: 1.0,
            sload_count: 3.0,
            call_count: 1.0,
            delegatecall_count: 0.0,
            staticcall_count: 1.0,
            create_count: 0.0,
            selfdestruct_count: 0.0,
            log_count: 1.0,
            revert_count: 0.0,
            reentrancy_depth: 0.0,
            eth_transferred_wei: 0.0,
            gas_ratio: 0.4,
            calldata_entropy: 3.5,
        };
        let score = detector.predict(&features);
        // Close to mean -> sigmoid near 0.5
        assert!(score < 0.65, "benign features should score low, got {score}");
    }

    #[test]
    fn anomaly_attack_features_high_score() {
        let detector = StatisticalAnomalyDetector::default();
        let features = FeatureVector {
            total_steps: 5000.0,
            unique_addresses: 20.0,
            max_call_depth: 10.0,
            sstore_count: 50.0,
            sload_count: 100.0,
            call_count: 30.0,
            delegatecall_count: 10.0,
            staticcall_count: 15.0,
            create_count: 5.0,
            selfdestruct_count: 2.0,
            log_count: 20.0,
            revert_count: 5.0,
            reentrancy_depth: 4.0,
            eth_transferred_wei: 5e18,
            gas_ratio: 0.99,
            calldata_entropy: 7.5,
        };
        let score = detector.predict(&features);
        assert!(
            score > 0.75,
            "attack features should score high, got {score}"
        );
    }

    #[test]
    fn anomaly_all_zero_features() {
        let detector = StatisticalAnomalyDetector::default();
        let features = FeatureVector::default();
        let score = detector.predict(&features);
        // All zeros should produce a valid score in [0, 1]
        assert!(
            (0.0..=1.0).contains(&score),
            "score must be in [0,1], got {score}"
        );
    }
}
