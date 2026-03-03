//! Calldata-based pre-filter for pending mempool transactions.
//!
//! Scans each transaction BEFORE execution using only calldata, value, and gas.
//! No receipts or logs are available — only TX-level data.
//! Target budget: <100us per scan.

use ethrex_common::types::{Transaction, TxKind};
use ethrex_common::{Address, H256, U256};
use rustc_hash::FxHashSet;

use super::config::MempoolMonitorConfig;
use super::types::{MempoolAlert, MempoolSuspicionReason};

// ---------------------------------------------------------------------------
// Known function selectors (first 4 bytes of keccak256)
// ---------------------------------------------------------------------------

/// Aave V2/V3 flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)
const SEL_AAVE_FLASH_LOAN: [u8; 4] = [0xab, 0x9c, 0x4b, 0x5d];

/// Uniswap V2 swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
const SEL_UNISWAP_V2_SWAP: [u8; 4] = [0x38, 0xed, 0x17, 0x38];

/// Uniswap V3 exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))
const SEL_UNISWAP_V3_EXACT_INPUT: [u8; 4] = [0x41, 0x4b, 0xf3, 0x89];

/// Balancer flashLoan(address,address[],uint256[],bytes)
const SEL_BALANCER_FLASH_LOAN: [u8; 4] = [0x5c, 0x38, 0x44, 0x9e];

/// Compound borrow(uint256)
const SEL_COMPOUND_BORROW: [u8; 4] = [0xc5, 0xeb, 0xea, 0xec];

/// multicall(bytes[]) — common on Uniswap V3 and other routers
const SEL_MULTICALL: [u8; 4] = [0xac, 0x96, 0x50, 0xd8];

/// Minimum init code size to flag contract creation (10 KB).
const SUSPICIOUS_INIT_CODE_SIZE: usize = 10 * 1024;

/// Default minimum gas limit for "high gas" heuristic.
#[cfg(test)]
const DEFAULT_MIN_GAS: u64 = 500_000;

// ---------------------------------------------------------------------------
// Known DeFi addresses (reused from pre_filter.rs via hex parsing)
// ---------------------------------------------------------------------------

fn addr(hex: &str) -> Address {
    let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).expect("valid hex address");
    Address::from_slice(&bytes)
}

fn default_known_defi_contracts() -> FxHashSet<Address> {
    let mut set = FxHashSet::default();
    // Flash loan providers
    set.insert(addr("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9")); // Aave V2
    set.insert(addr("87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2")); // Aave V3
    set.insert(addr("BA12222222228d8Ba445958a75a0704d566BF2C8")); // Balancer Vault
    // DEX routers
    set.insert(addr("7a250d5630B4cF539739dF2C5dAcb4c659F2488D")); // Uniswap V2 Router
    set.insert(addr("E592427A0AEce92De3Edee1F18E0157C05861564")); // Uniswap V3 Router
    set.insert(addr("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45")); // Uniswap V3 Router02
    set.insert(addr("d9e1cE17f2641f24aE83637AB66a2cca9C378532")); // SushiSwap Router
    set.insert(addr("bEbc44782C7dB0a1A60Cb6fe97d0b483032F24Cb")); // Curve 3pool
    set.insert(addr("1111111254EEB25477B68fb85Ed929f73A960582")); // 1inch V5
    // Lending
    set.insert(addr("3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B")); // Compound Comptroller
    set.insert(addr("44fbEbAD54DE9076c82bAb6EaebcD01292838dE4")); // Cream Finance
    set
}

fn default_known_selectors() -> FxHashSet<[u8; 4]> {
    let mut set = FxHashSet::default();
    set.insert(SEL_AAVE_FLASH_LOAN);
    set.insert(SEL_UNISWAP_V2_SWAP);
    set.insert(SEL_UNISWAP_V3_EXACT_INPUT);
    set.insert(SEL_BALANCER_FLASH_LOAN);
    set.insert(SEL_COMPOUND_BORROW);
    set
}

// ---------------------------------------------------------------------------
// MempoolPreFilter
// ---------------------------------------------------------------------------

/// Stateless, immutable pre-filter for pending mempool transactions.
///
/// All heuristics operate on calldata, value, gas, and target address only.
/// No Mutex needed — can be shared freely via `Arc`.
pub struct MempoolPreFilter {
    known_selectors: FxHashSet<[u8; 4]>,
    known_defi_contracts: FxHashSet<Address>,
    min_value_wei: U256,
    min_gas: u64,
}

impl MempoolPreFilter {
    /// Create a new filter with the given configuration.
    pub fn new(config: &MempoolMonitorConfig) -> Self {
        let min_value_wei =
            U256::from((config.min_value_eth * 1_000_000_000_000_000_000.0) as u128);
        Self {
            known_selectors: default_known_selectors(),
            known_defi_contracts: default_known_defi_contracts(),
            min_value_wei,
            min_gas: config.min_gas,
        }
    }

    /// Create a filter with custom known selectors and contracts (for testing).
    #[cfg(test)]
    pub fn with_custom(
        selectors: FxHashSet<[u8; 4]>,
        contracts: FxHashSet<Address>,
        min_value_wei: U256,
        min_gas: u64,
    ) -> Self {
        Self {
            known_selectors: selectors,
            known_defi_contracts: contracts,
            min_value_wei,
            min_gas,
        }
    }

    /// Scan a single pending transaction. Returns `Some(MempoolAlert)` if suspicious.
    pub fn scan_transaction(
        &self,
        tx: &Transaction,
        sender: Address,
        tx_hash: H256,
    ) -> Option<MempoolAlert> {
        let mut reasons = Vec::new();
        let data = tx.data();
        let value = tx.value();
        let gas_limit = tx.gas_limit();
        let target = match tx.to() {
            TxKind::Call(addr) => Some(addr),
            TxKind::Create => None,
        };

        // Heuristic 1: Flash loan selector match
        if data.len() >= 4 {
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&data[..4]);
            if self.known_selectors.contains(&selector) {
                reasons.push(MempoolSuspicionReason::FlashLoanSelector { selector });
            }
        }

        // Heuristic 2: High value + known DeFi contract
        if let Some(target_addr) = target {
            if value >= self.min_value_wei && self.known_defi_contracts.contains(&target_addr) {
                reasons.push(MempoolSuspicionReason::HighValueDeFi {
                    value_wei: value,
                    target: target_addr,
                });
            }

            // Heuristic 3: High gas + known contract
            if gas_limit >= self.min_gas && self.known_defi_contracts.contains(&target_addr) {
                reasons.push(MempoolSuspicionReason::HighGasKnownContract {
                    gas_limit,
                    target: target_addr,
                });
            }

            // Heuristic 5: Multicall pattern on known DeFi router
            if data.len() >= 4 {
                let mut selector = [0u8; 4];
                selector.copy_from_slice(&data[..4]);
                if selector == SEL_MULTICALL && self.known_defi_contracts.contains(&target_addr) {
                    reasons.push(MempoolSuspicionReason::MulticallPattern {
                        target: target_addr,
                    });
                }
            }
        }

        // Heuristic 4: Suspicious contract creation (large init code)
        if target.is_none() && data.len() >= SUSPICIOUS_INIT_CODE_SIZE {
            reasons.push(MempoolSuspicionReason::SuspiciousContractCreation {
                init_code_size: data.len(),
            });
        }

        if reasons.is_empty() {
            return None;
        }

        let score = reasons.iter().map(|r| r.score()).sum::<f64>().min(1.0);

        Some(MempoolAlert {
            tx_hash,
            sender,
            target,
            reasons,
            score,
        })
    }
}

impl Default for MempoolPreFilter {
    fn default() -> Self {
        Self::new(&MempoolMonitorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ethrex_common::types::{LegacyTransaction, TxKind};

    fn make_call_tx(to: Address, value: U256, gas: u64, data: Vec<u8>) -> Transaction {
        Transaction::LegacyTransaction(LegacyTransaction {
            gas,
            to: TxKind::Call(to),
            value,
            data: Bytes::from(data),
            ..Default::default()
        })
    }

    fn make_create_tx(value: U256, gas: u64, data: Vec<u8>) -> Transaction {
        Transaction::LegacyTransaction(LegacyTransaction {
            gas,
            to: TxKind::Create,
            value,
            data: Bytes::from(data),
            ..Default::default()
        })
    }

    fn test_sender() -> Address {
        Address::from_low_u64_be(0x1234)
    }

    fn test_hash() -> H256 {
        H256::from_low_u64_be(0xABCD)
    }

    fn known_contract() -> Address {
        // Uniswap V2 Router
        addr("7a250d5630B4cF539739dF2C5dAcb4c659F2488D")
    }

    fn unknown_contract() -> Address {
        Address::from_low_u64_be(0x9999)
    }

    // -- Flash loan selector tests --

    #[test]
    fn flash_loan_known_selector_match() {
        let filter = MempoolPreFilter::default();
        let mut data = SEL_AAVE_FLASH_LOAN.to_vec();
        data.extend_from_slice(&[0u8; 64]); // padding
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, data);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert
            .reasons
            .iter()
            .any(|r| matches!(r, MempoolSuspicionReason::FlashLoanSelector { .. })));
    }

    #[test]
    fn flash_loan_unknown_selector() {
        let filter = MempoolPreFilter::default();
        let data = vec![0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x00];
        let tx = make_call_tx(unknown_contract(), U256::zero(), 100_000, data);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::FlashLoanSelector { .. })));
        }
    }

    #[test]
    fn flash_loan_empty_calldata() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, vec![]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::FlashLoanSelector { .. })));
        }
    }

    #[test]
    fn flash_loan_partial_selector() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, vec![0xAB, 0x9C]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::FlashLoanSelector { .. })));
        }
    }

    // -- High value DeFi tests --

    #[test]
    fn high_value_defi_above_threshold() {
        let filter = MempoolPreFilter::default();
        let value = U256::from(11_000_000_000_000_000_000_u128); // 11 ETH > default 10
        let tx = make_call_tx(known_contract(), value, 100_000, vec![0; 4]);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert
            .reasons
            .iter()
            .any(|r| matches!(r, MempoolSuspicionReason::HighValueDeFi { .. })));
    }

    #[test]
    fn high_value_defi_below_threshold() {
        let filter = MempoolPreFilter::default();
        let value = U256::from(1_000_000_000_000_000_000_u64); // 1 ETH < default 10
        let tx = make_call_tx(known_contract(), value, 100_000, vec![0; 4]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        // Should not flag for HighValueDeFi
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::HighValueDeFi { .. })));
        }
    }

    #[test]
    fn high_value_defi_unknown_contract() {
        let filter = MempoolPreFilter::default();
        let value = U256::from(100_000_000_000_000_000_000_u128); // 100 ETH
        let tx = make_call_tx(unknown_contract(), value, 100_000, vec![0; 4]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::HighValueDeFi { .. })));
        }
    }

    // -- High gas + known contract tests --

    #[test]
    fn high_gas_known_contract_above_threshold() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(known_contract(), U256::zero(), 600_000, vec![0; 4]);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert
            .reasons
            .iter()
            .any(|r| matches!(r, MempoolSuspicionReason::HighGasKnownContract { .. })));
    }

    #[test]
    fn high_gas_below_threshold() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(known_contract(), U256::zero(), 400_000, vec![0; 4]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::HighGasKnownContract { .. })));
        }
    }

    #[test]
    fn high_gas_unknown_contract() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(unknown_contract(), U256::zero(), 600_000, vec![0; 4]);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::HighGasKnownContract { .. })));
        }
    }

    // -- Contract creation tests --

    #[test]
    fn suspicious_contract_creation_large_init_code() {
        let filter = MempoolPreFilter::default();
        let data = vec![0xAA; 15_000]; // 15KB > 10KB threshold
        let tx = make_create_tx(U256::zero(), 1_000_000, data);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert.reasons.iter().any(
            |r| matches!(r, MempoolSuspicionReason::SuspiciousContractCreation { init_code_size } if *init_code_size == 15_000)
        ));
    }

    #[test]
    fn contract_creation_small_init_code() {
        let filter = MempoolPreFilter::default();
        let data = vec![0xBB; 5_000]; // 5KB < 10KB threshold
        let tx = make_create_tx(U256::zero(), 1_000_000, data);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::SuspiciousContractCreation { .. })));
        }
    }

    #[test]
    fn normal_call_tx_not_flagged_as_creation() {
        let filter = MempoolPreFilter::default();
        let data = vec![0xCC; 20_000]; // Large data but it's a CALL, not CREATE
        let tx = make_call_tx(unknown_contract(), U256::zero(), 100_000, data);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::SuspiciousContractCreation { .. })));
        }
    }

    // -- Multicall tests --

    #[test]
    fn multicall_on_known_router() {
        let filter = MempoolPreFilter::default();
        let mut data = SEL_MULTICALL.to_vec();
        data.extend_from_slice(&[0; 64]);
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, data);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert
            .reasons
            .iter()
            .any(|r| matches!(r, MempoolSuspicionReason::MulticallPattern { .. })));
    }

    #[test]
    fn non_multicall_selector() {
        let filter = MempoolPreFilter::default();
        let data = vec![0x11, 0x22, 0x33, 0x44]; // random selector
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, data);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::MulticallPattern { .. })));
        }
    }

    #[test]
    fn multicall_on_unknown_contract() {
        let filter = MempoolPreFilter::default();
        let mut data = SEL_MULTICALL.to_vec();
        data.extend_from_slice(&[0; 64]);
        let tx = make_call_tx(unknown_contract(), U256::zero(), 100_000, data);

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        if let Some(a) = &alert {
            assert!(!a
                .reasons
                .iter()
                .any(|r| matches!(r, MempoolSuspicionReason::MulticallPattern { .. })));
        }
    }

    // -- Integration tests --

    #[test]
    fn score_is_sum_of_reasons_capped_at_1() {
        let filter = MempoolPreFilter::default();
        // Flash loan selector + high gas known contract = 0.4 + 0.2 = 0.6
        let mut data = SEL_AAVE_FLASH_LOAN.to_vec();
        data.extend_from_slice(&[0; 64]);
        let tx = make_call_tx(known_contract(), U256::zero(), 600_000, data);

        let alert = filter
            .scan_transaction(&tx, test_sender(), test_hash())
            .expect("should flag");
        assert!(alert.score > 0.5);
        assert!(alert.score <= 1.0);
    }

    #[test]
    fn completely_benign_tx() {
        let filter = MempoolPreFilter::default();
        let tx = make_call_tx(
            unknown_contract(),
            U256::from(100u64),
            21_000,
            vec![0; 4],
        );

        let alert = filter.scan_transaction(&tx, test_sender(), test_hash());
        assert!(alert.is_none());
    }

    #[test]
    fn alert_contains_correct_sender_and_hash() {
        let filter = MempoolPreFilter::default();
        let mut data = SEL_AAVE_FLASH_LOAN.to_vec();
        data.extend_from_slice(&[0; 64]);
        let sender = Address::from_low_u64_be(0xDEAD);
        let hash = H256::from_low_u64_be(0xBEEF);
        let tx = make_call_tx(known_contract(), U256::zero(), 100_000, data);

        let alert = filter
            .scan_transaction(&tx, sender, hash)
            .expect("should flag");
        assert_eq!(alert.sender, sender);
        assert_eq!(alert.tx_hash, hash);
        assert_eq!(alert.target, Some(known_contract()));
    }

    #[test]
    fn default_filter_matches_default_config() {
        let filter = MempoolPreFilter::default();
        // Verify the default min_gas matches DEFAULT_MIN_GAS
        assert_eq!(filter.min_gas, DEFAULT_MIN_GAS);
    }
}
