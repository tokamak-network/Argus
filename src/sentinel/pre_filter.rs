//! Receipt-based pre-filter for detecting suspicious transactions.
//!
//! Scans every TX receipt in a block using lightweight heuristics (~10-50μs per TX).
//! Suspicious transactions are flagged for deep analysis via the Autopsy Lab pipeline.

use ethrex_common::types::{BlockHeader, Log, Receipt, Transaction, TxKind};
use ethrex_common::{Address, U256};
use rustc_hash::FxHashSet;

use super::types::*;

/// ERC-20 Transfer(address,address,uint256) event topic prefix (first 4 bytes).
const TRANSFER_TOPIC_PREFIX: [u8; 4] = [0xdd, 0xf2, 0x52, 0xad];

// ---------------------------------------------------------------------------
// Flash loan event topic prefixes (first 4 bytes of keccak256)
// ---------------------------------------------------------------------------

/// Aave V2/V3 FlashLoan(address,address,address,uint256,uint256,uint16)
const FLASH_LOAN_AAVE: [u8; 4] = [0x63, 0x10, 0x42, 0xc8];

/// Balancer FlashLoan(address,address,uint256,uint256)
const FLASH_LOAN_BALANCER: [u8; 4] = [0x0d, 0x7d, 0x75, 0xe0];

/// Uniswap V3 Flash(address,address,uint256,uint256,uint256,uint256)
const FLASH_LOAN_UNISWAP_V3: [u8; 4] = [0xbd, 0xbd, 0xb7, 0x16];

// ---------------------------------------------------------------------------
// Well-known mainnet addresses (built at runtime via from_slice)
// ---------------------------------------------------------------------------

fn addr(hex: &str) -> Address {
    let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).expect("valid hex address");
    Address::from_slice(&bytes)
}

/// Known DeFi contract addresses with labels.
/// Returns (address, label, category) tuples.
fn known_address_db() -> Vec<(Address, &'static str, AddressCategory)> {
    vec![
        // Flash loan providers
        (
            addr("7d2768de32b0b80b7a3454c06bdac94a69ddc7a9"),
            "Aave V2 Pool",
            AddressCategory::FlashLoan,
        ),
        (
            addr("87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"),
            "Aave V3 Pool",
            AddressCategory::FlashLoan,
        ),
        (
            addr("BA12222222228d8Ba445958a75a0704d566BF2C8"),
            "Balancer Vault",
            AddressCategory::Dex,
        ),
        // Oracles
        (
            addr("5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"),
            "Chainlink ETH/USD",
            AddressCategory::Oracle,
        ),
        (
            addr("F4030B9d1859681AD26495ec8C9934dd2E352bb9"),
            "Chainlink BTC/USD",
            AddressCategory::Oracle,
        ),
        (
            addr("8fFfFfd4AfB6115b954Bd326cda7E60e2fBdCe36"),
            "Chainlink USDC/USD",
            AddressCategory::Oracle,
        ),
        // DEX
        (
            addr("7a250d5630B4cF539739dF2C5dAcb4c659F2488D"),
            "Uniswap V2 Router",
            AddressCategory::Dex,
        ),
        (
            addr("E592427A0AEce92De3Edee1F18E0157C05861564"),
            "Uniswap V3 Router",
            AddressCategory::Dex,
        ),
        (
            addr("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
            "Uniswap V3 Router 02",
            AddressCategory::Dex,
        ),
        (
            addr("d9e1cE17f2641f24aE83637AB66a2cca9C378532"),
            "SushiSwap Router",
            AddressCategory::Dex,
        ),
        (
            addr("bEbc44782C7dB0a1A60Cb6fe97d0b483032F24Cb"),
            "Curve 3pool",
            AddressCategory::Dex,
        ),
        (
            addr("1111111254EEB25477B68fb85Ed929f73A960582"),
            "1inch V5 Router",
            AddressCategory::Dex,
        ),
        // Lending
        (
            addr("3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B"),
            "Compound Comptroller",
            AddressCategory::Lending,
        ),
        (
            addr("44fbEbAD54DE9076c82bAb6EaebcD01292838dE4"),
            "Cream Finance",
            AddressCategory::Lending,
        ),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressCategory {
    FlashLoan,
    Oracle,
    Dex,
    Lending,
}

/// Receipt-based pre-filter for suspicious transaction detection.
pub struct PreFilter {
    config: SentinelConfig,
    flash_loan_prefixes: Vec<[u8; 4]>,
    /// (address → label) for all known contracts.
    address_labels: Vec<(Address, &'static str)>,
    oracle_addresses: FxHashSet<Address>,
    dex_addresses: FxHashSet<Address>,
}

impl PreFilter {
    /// Create a new pre-filter with the given configuration.
    pub fn new(config: SentinelConfig) -> Self {
        let flash_loan_prefixes = vec![FLASH_LOAN_AAVE, FLASH_LOAN_BALANCER, FLASH_LOAN_UNISWAP_V3];

        let db = known_address_db();

        let address_labels: Vec<(Address, &'static str)> =
            db.iter().map(|(a, l, _)| (*a, *l)).collect();

        let oracle_addresses: FxHashSet<Address> = db
            .iter()
            .filter(|(_, _, cat)| *cat == AddressCategory::Oracle)
            .map(|(a, _, _)| *a)
            .collect();

        let dex_addresses: FxHashSet<Address> = db
            .iter()
            .filter(|(_, _, cat)| *cat == AddressCategory::Dex)
            .map(|(a, _, _)| *a)
            .collect();

        Self {
            config,
            flash_loan_prefixes,
            address_labels,
            oracle_addresses,
            dex_addresses,
        }
    }

    /// Scan an entire block's receipts for suspicious transactions.
    pub fn scan_block(
        &self,
        transactions: &[Transaction],
        receipts: &[Receipt],
        header: &BlockHeader,
    ) -> Vec<SuspiciousTx> {
        transactions
            .iter()
            .zip(receipts.iter())
            .enumerate()
            .filter_map(|(idx, (tx, receipt))| self.scan_tx(tx, receipt, idx, header))
            .collect()
    }

    /// Scan a single transaction receipt. Returns `Some` if suspicious.
    pub fn scan_tx(
        &self,
        tx: &Transaction,
        receipt: &Receipt,
        tx_index: usize,
        _header: &BlockHeader,
    ) -> Option<SuspiciousTx> {
        let mut reasons = Vec::new();

        // Heuristic 1: Flash loan signature
        if let Some(provider) = self.check_flash_loan_signature(&receipt.logs) {
            reasons.push(SuspicionReason::FlashLoanSignature {
                provider_address: provider,
            });
        }

        // Heuristic 2: High value + revert
        if let Some((value, gas)) = self.check_high_value_revert(tx, receipt) {
            reasons.push(SuspicionReason::HighValueWithRevert {
                value_wei: value,
                gas_used: gas,
            });
        }

        // Heuristic 3: Multiple ERC-20 transfers
        let erc20_count = self.count_erc20_transfers(&receipt.logs);
        if erc20_count >= self.config.min_erc20_transfers {
            reasons.push(SuspicionReason::MultipleErc20Transfers { count: erc20_count });
        }

        // Heuristic 4: Known contract interaction
        if let Some((addr, label)) = self.check_known_contract(tx, &receipt.logs) {
            reasons.push(SuspicionReason::KnownContractInteraction {
                address: addr,
                label,
            });
        }

        // Heuristic 5: Unusual gas pattern
        if let Some((gas_used, gas_limit)) = self.check_unusual_gas(tx, receipt) {
            reasons.push(SuspicionReason::UnusualGasPattern {
                gas_used,
                gas_limit,
            });
        }

        // Heuristic 6: Self-destruct indicators
        if self.check_self_destruct(receipt) {
            reasons.push(SuspicionReason::SelfDestructDetected);
        }

        // Heuristic 7: Price oracle + swap
        if let Some(oracle) = self.check_price_oracle_swap(&receipt.logs) {
            reasons.push(SuspicionReason::PriceOracleWithSwap { oracle });
        }

        if reasons.is_empty() {
            return None;
        }

        let score: f64 = reasons.iter().map(|r| r.score()).sum();
        if score < self.config.suspicion_threshold {
            return None;
        }

        let priority = AlertPriority::from_score(score);
        Some(SuspiciousTx {
            tx_hash: tx.hash(),
            tx_index,
            reasons,
            score,
            priority,
        })
    }

    // -----------------------------------------------------------------------
    // Heuristic implementations
    // -----------------------------------------------------------------------

    /// H1: Check logs for known flash loan event signatures.
    fn check_flash_loan_signature(&self, logs: &[Log]) -> Option<Address> {
        for log in logs {
            if let Some(topic) = log.topics.first() {
                let prefix: [u8; 4] = topic.as_bytes()[..4].try_into().unwrap_or_default();
                if self.flash_loan_prefixes.contains(&prefix) {
                    return Some(log.address);
                }
            }
        }
        None
    }

    /// H2: Check for reverted TX with high value and significant gas usage.
    fn check_high_value_revert(&self, tx: &Transaction, receipt: &Receipt) -> Option<(U256, u64)> {
        if receipt.succeeded {
            return None;
        }
        let gas_used = receipt.cumulative_gas_used;
        if gas_used < 100_000 {
            return None;
        }

        let value = tx.value();
        // Check native ETH value
        if value >= self.config.min_value_wei {
            return Some((value, gas_used));
        }

        // Also flag if there are large ERC-20 Transfer events in a reverted TX
        let has_large_erc20 = self.count_erc20_transfers(&receipt.logs) >= 3;
        if has_large_erc20 {
            return Some((value, gas_used));
        }

        None
    }

    /// H3: Count ERC-20 Transfer events (LOG3 with Transfer topic prefix).
    fn count_erc20_transfers(&self, logs: &[Log]) -> usize {
        logs.iter()
            .filter(|log| {
                log.topics.len() >= 3
                    && log
                        .topics
                        .first()
                        .map(|t| t.as_bytes()[..4] == TRANSFER_TOPIC_PREFIX)
                        .unwrap_or(false)
            })
            .count()
    }

    /// H4: Check if TX interacts with known high-value DeFi contracts.
    fn check_known_contract(&self, tx: &Transaction, logs: &[Log]) -> Option<(Address, String)> {
        // Check tx.to
        if let TxKind::Call(to_addr) = tx.to()
            && let Some(label) = self.label_address(&to_addr)
        {
            return Some((to_addr, label));
        }
        // Check log emitting addresses
        for log in logs {
            if let Some(label) = self.label_address(&log.address) {
                return Some((log.address, label));
            }
        }
        None
    }

    /// H5: Check for unusual gas usage pattern (near-exact gas estimation).
    fn check_unusual_gas(&self, tx: &Transaction, receipt: &Receipt) -> Option<(u64, u64)> {
        let gas_limit = tx.gas_limit();
        let gas_used = receipt.cumulative_gas_used;
        if gas_limit == 0 {
            return None;
        }
        let ratio = gas_used as f64 / gas_limit as f64;
        if ratio > self.config.gas_ratio_threshold && gas_used > self.config.min_gas_used {
            Some((gas_used, gas_limit))
        } else {
            None
        }
    }

    /// H6: Detect self-destruct indicators.
    ///
    /// SELFDESTRUCT doesn't produce a standard LOG event, so this is a heuristic:
    /// high gas usage with very few logs suggests potential self-destruct activity.
    fn check_self_destruct(&self, receipt: &Receipt) -> bool {
        // High gas but zero or very few logs — possible self-destruct
        // This is a weak heuristic; deep analysis confirms it via opcode trace
        let gas_used = receipt.cumulative_gas_used;
        gas_used > 1_000_000 && receipt.logs.is_empty() && !receipt.succeeded
    }

    /// H7: Check if both oracle and DEX addresses appear in log addresses.
    fn check_price_oracle_swap(&self, logs: &[Log]) -> Option<Address> {
        let mut found_oracle: Option<Address> = None;
        let mut found_dex = false;

        for log in logs {
            if self.oracle_addresses.contains(&log.address) {
                found_oracle = Some(log.address);
            }
            if self.dex_addresses.contains(&log.address) {
                found_dex = true;
            }
        }

        if found_dex { found_oracle } else { None }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Return a static label for known contract addresses.
    fn label_address(&self, address: &Address) -> Option<String> {
        self.address_labels
            .iter()
            .find(|(a, _)| a == address)
            .map(|(_, label)| label.to_string())
    }
}

impl Default for PreFilter {
    fn default() -> Self {
        Self::new(SentinelConfig::default())
    }
}
