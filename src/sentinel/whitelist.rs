//! DeFi protocol whitelist engine for false-positive reduction.
//!
//! Like a bouncer checking IDs at the door — known DeFi protocols get their
//! suspicion scores reduced because their normal operations (flash loans, swaps)
//! look suspicious to generic heuristics.
//!
//! All whitelist entries are loaded from TOML configuration. No addresses are
//! hardcoded in source code.

use ethrex_common::Address;
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

/// Category of a whitelisted DeFi protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum WhitelistCategory {
    /// Flash loan providers (Balancer, Aave).
    FlashLoan,
    /// Decentralized exchanges (Uniswap, Curve).
    #[serde(alias = "Dex")]
    DEX,
    /// Lending protocols (Compound, Aave).
    Lending,
    /// Cross-chain bridges (Across, Stargate).
    Bridge,
}

/// A single whitelist entry loaded from TOML configuration.
///
/// ```toml
/// [[sentinel.whitelist.entries]]
/// address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"
/// protocol = "Balancer Vault"
/// category = "FlashLoan"
/// score_modifier = -0.4
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// Contract address (hex string in TOML, converted to Address at load time).
    #[serde(
        deserialize_with = "deserialize_address",
        serialize_with = "serialize_address"
    )]
    pub address: Address,
    /// Human-readable protocol name.
    pub protocol: String,
    /// Protocol classification.
    pub category: WhitelistCategory,
    /// Score adjustment (-1.0 to 0.0). Applied when this address appears in a TX.
    pub score_modifier: f64,
}

/// TOML-level whitelist configuration section.
///
/// ```toml
/// [sentinel.whitelist]
/// entries = [...]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WhitelistConfig {
    /// List of whitelisted protocol entries.
    pub entries: Vec<WhitelistEntry>,
}

/// Engine that checks transactions against the whitelist.
///
/// Constructed from a `WhitelistConfig` at sentinel startup. If the config
/// fails to load, an empty engine is created (no addresses whitelisted).
#[derive(Debug, Clone)]
pub struct WhitelistEngine {
    entries: FxHashMap<Address, WhitelistEntry>,
}

/// Result of checking an address against the whitelist.
#[derive(Debug, Clone)]
pub struct WhitelistMatch {
    pub protocol: String,
    pub category: WhitelistCategory,
    pub score_modifier: f64,
}

impl WhitelistEngine {
    /// Create a new engine from configuration.
    pub fn new(config: WhitelistConfig) -> Self {
        let entries = config.entries.into_iter().map(|e| (e.address, e)).collect();
        Self { entries }
    }

    /// Create an empty engine (no whitelisted addresses).
    pub fn empty() -> Self {
        Self {
            entries: FxHashMap::default(),
        }
    }

    /// Check if an address is whitelisted. Returns the match details if found.
    pub fn check_address(&self, address: &Address) -> Option<WhitelistMatch> {
        self.entries.get(address).map(|entry| WhitelistMatch {
            protocol: entry.protocol.clone(),
            category: entry.category.clone(),
            score_modifier: entry.score_modifier,
        })
    }

    /// Check multiple addresses and return all matches with the total score modifier.
    ///
    /// Returns `(matches, total_modifier)` where `total_modifier` is the sum of
    /// all matched entries' `score_modifier` values (clamped to [-1.0, 0.0]).
    pub fn check_addresses(&self, addresses: &[Address]) -> (Vec<WhitelistMatch>, f64) {
        let mut matches = Vec::new();
        let mut seen = rustc_hash::FxHashSet::default();

        for addr in addresses {
            // Deduplicate: same address appearing multiple times counts once
            if !seen.insert(*addr) {
                continue;
            }
            if let Some(m) = self.check_address(addr) {
                matches.push(m);
            }
        }

        let total_modifier: f64 = matches.iter().map(|m| m.score_modifier).sum();
        let clamped = total_modifier.clamp(-1.0, 0.0);

        (matches, clamped)
    }

    /// Returns true if the engine has no entries (empty whitelist).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of whitelisted entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl WhitelistConfig {
    /// Validate whitelist configuration entries.
    pub fn validate(&self) -> Result<(), String> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.score_modifier > 0.0 {
                return Err(format!(
                    "whitelist entry [{}] '{}': score_modifier must be <= 0.0, got {}",
                    i, entry.protocol, entry.score_modifier
                ));
            }
            if entry.score_modifier < -1.0 {
                return Err(format!(
                    "whitelist entry [{}] '{}': score_modifier must be >= -1.0, got {}",
                    i, entry.protocol, entry.score_modifier
                ));
            }
            if entry.protocol.is_empty() {
                return Err(format!(
                    "whitelist entry [{}]: protocol name must not be empty",
                    i
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Serde helpers for Address (H160) ↔ hex string
// ---------------------------------------------------------------------------

fn deserialize_address<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let hex_str = s.strip_prefix("0x").unwrap_or(&s);
    let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
    if bytes.len() != 20 {
        return Err(serde::de::Error::custom(format!(
            "address must be 20 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(Address::from_slice(&bytes))
}

fn serialize_address<S>(address: &Address, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let hex_string = format!("0x{}", hex::encode(address.as_bytes()));
    serializer.serialize_str(&hex_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(hex: &str) -> Address {
        let bytes = hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).expect("valid hex");
        Address::from_slice(&bytes)
    }

    fn sample_config() -> WhitelistConfig {
        WhitelistConfig {
            entries: vec![
                WhitelistEntry {
                    address: test_address("BA12222222228d8Ba445958a75a0704d566BF2C8"),
                    protocol: "Balancer Vault".to_string(),
                    category: WhitelistCategory::FlashLoan,
                    score_modifier: -0.4,
                },
                WhitelistEntry {
                    address: test_address("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"),
                    protocol: "Uniswap SwapRouter02".to_string(),
                    category: WhitelistCategory::DEX,
                    score_modifier: -0.3,
                },
            ],
        }
    }

    #[test]
    fn engine_matches_known_address() {
        let engine = WhitelistEngine::new(sample_config());
        let addr = test_address("BA12222222228d8Ba445958a75a0704d566BF2C8");
        let result = engine.check_address(&addr);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.protocol, "Balancer Vault");
        assert_eq!(m.category, WhitelistCategory::FlashLoan);
        assert!((m.score_modifier - (-0.4)).abs() < f64::EPSILON);
    }

    #[test]
    fn engine_returns_none_for_unknown_address() {
        let engine = WhitelistEngine::new(sample_config());
        let addr = test_address("0000000000000000000000000000000000000001");
        assert!(engine.check_address(&addr).is_none());
    }

    #[test]
    fn engine_empty_has_no_entries() {
        let engine = WhitelistEngine::empty();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);
    }

    #[test]
    fn check_addresses_deduplicates() {
        let engine = WhitelistEngine::new(sample_config());
        let addr = test_address("BA12222222228d8Ba445958a75a0704d566BF2C8");
        let (matches, modifier) = engine.check_addresses(&[addr, addr, addr]);
        assert_eq!(matches.len(), 1);
        assert!((modifier - (-0.4)).abs() < f64::EPSILON);
    }

    #[test]
    fn check_addresses_sums_modifiers() {
        let engine = WhitelistEngine::new(sample_config());
        let addr1 = test_address("BA12222222228d8Ba445958a75a0704d566BF2C8");
        let addr2 = test_address("68b3465833fb72A70ecDF485E0e4C7bD8665Fc45");
        let (matches, modifier) = engine.check_addresses(&[addr1, addr2]);
        assert_eq!(matches.len(), 2);
        assert!((modifier - (-0.7)).abs() < f64::EPSILON);
    }

    #[test]
    fn check_addresses_clamps_total() {
        let config = WhitelistConfig {
            entries: vec![
                WhitelistEntry {
                    address: test_address("0000000000000000000000000000000000000001"),
                    protocol: "Proto A".to_string(),
                    category: WhitelistCategory::FlashLoan,
                    score_modifier: -0.6,
                },
                WhitelistEntry {
                    address: test_address("0000000000000000000000000000000000000002"),
                    protocol: "Proto B".to_string(),
                    category: WhitelistCategory::Lending,
                    score_modifier: -0.6,
                },
            ],
        };
        let engine = WhitelistEngine::new(config);
        let addr1 = test_address("0000000000000000000000000000000000000001");
        let addr2 = test_address("0000000000000000000000000000000000000002");
        let (_matches, modifier) = engine.check_addresses(&[addr1, addr2]);
        // -0.6 + -0.6 = -1.2 but clamped to -1.0
        assert!((modifier - (-1.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn validate_rejects_positive_score_modifier() {
        let config = WhitelistConfig {
            entries: vec![WhitelistEntry {
                address: test_address("0000000000000000000000000000000000000001"),
                protocol: "Bad Entry".to_string(),
                category: WhitelistCategory::DEX,
                score_modifier: 0.5,
            }],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_too_negative_modifier() {
        let config = WhitelistConfig {
            entries: vec![WhitelistEntry {
                address: test_address("0000000000000000000000000000000000000001"),
                protocol: "Bad Entry".to_string(),
                category: WhitelistCategory::DEX,
                score_modifier: -1.5,
            }],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_protocol_name() {
        let config = WhitelistConfig {
            entries: vec![WhitelistEntry {
                address: test_address("0000000000000000000000000000000000000001"),
                protocol: String::new(),
                category: WhitelistCategory::DEX,
                score_modifier: -0.3,
            }],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_accepts_valid_config() {
        let config = sample_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn toml_roundtrip() {
        let config = sample_config();
        let serialized = toml::to_string(&config).expect("serialize");
        let deserialized: WhitelistConfig = toml::from_str(&serialized).expect("deserialize");
        assert_eq!(deserialized.entries.len(), 2);
        assert_eq!(deserialized.entries[0].protocol, "Balancer Vault");
        assert_eq!(
            deserialized.entries[0].category,
            WhitelistCategory::FlashLoan
        );
    }

    #[test]
    fn toml_deserialization_from_spec_format() {
        let toml_str = r#"
entries = [
    { address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8", protocol = "Balancer Vault", category = "FlashLoan", score_modifier = -0.4 },
    { address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", protocol = "Aave V3 Pool", category = "Lending", score_modifier = -0.35 },
]
"#;
        let config: WhitelistConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.entries.len(), 2);
        assert_eq!(config.entries[1].protocol, "Aave V3 Pool");
        assert_eq!(config.entries[1].category, WhitelistCategory::Lending);
    }
}
