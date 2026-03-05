//! Whitelist TOML parsing: string-based TOML types → domain types.
//!
//! This module defines the TOML-facing configuration structs for the DeFi
//! whitelist (`WhitelistTomlConfig`, `WhitelistEntryToml`) and the helper
//! functions that convert them into domain types defined in [`super::whitelist`].

use ethrex_common::Address;
use serde::{Deserialize, Serialize};

use super::whitelist::{WhitelistCategory, WhitelistEntry};

// ---------------------------------------------------------------------------
// Whitelist TOML configuration
// ---------------------------------------------------------------------------

/// The `[sentinel.whitelist]` section in the TOML config.
///
/// Uses plain strings for addresses and categories so that TOML stays readable
/// and parsing errors are handled gracefully (invalid entries are skipped, not
/// fatal). Converted to domain types via [`super::config::SentinelFullConfig::to_whitelist_engine`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WhitelistTomlConfig {
    /// List of whitelisted protocol entries.
    pub entries: Vec<WhitelistEntryToml>,
}

/// A single whitelisted contract entry in TOML format.
///
/// ```toml
/// [[sentinel.whitelist.entries]]
/// address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"
/// protocol = "Balancer Vault"
/// category = "FlashLoan"
/// score_modifier = -0.4
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntryToml {
    /// Hex-encoded contract address (with `0x` prefix).
    pub address: String,
    /// Human-readable protocol name.
    pub protocol: String,
    /// Protocol category: `"FlashLoan"`, `"DEX"`, `"Lending"`, or `"Bridge"`.
    pub category: String,
    /// Score adjustment applied when this address is involved (`-1.0..=0.0`).
    pub score_modifier: f64,
}

impl WhitelistEntryToml {
    /// Convert this TOML entry to a domain [`WhitelistEntry`].
    ///
    /// Returns an error string if the address hex is invalid or the category
    /// is not recognised.
    pub(crate) fn to_whitelist_entry(&self) -> Result<WhitelistEntry, String> {
        if self.score_modifier > 0.0 || self.score_modifier < -1.0 {
            return Err(format!(
                "score_modifier must be in [-1.0, 0.0], got {}",
                self.score_modifier
            ));
        }
        let address = parse_hex_address(&self.address)?;
        let category = parse_whitelist_category(&self.category)?;
        Ok(WhitelistEntry {
            address,
            protocol: self.protocol.clone(),
            category,
            score_modifier: self.score_modifier,
        })
    }
}

/// Parse a `"0x..."` hex string into an [`Address`] (H160).
pub(crate) fn parse_hex_address(s: &str) -> Result<Address, String> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex address '{}': {}", s, e))?;
    if bytes.len() != 20 {
        return Err(format!(
            "address must be 20 bytes, got {} ('{}')",
            bytes.len(),
            s
        ));
    }
    Ok(Address::from_slice(&bytes))
}

/// Parse a category string into a [`WhitelistCategory`] enum.
pub(crate) fn parse_whitelist_category(s: &str) -> Result<WhitelistCategory, String> {
    match s {
        "FlashLoan" => Ok(WhitelistCategory::FlashLoan),
        "DEX" | "Dex" => Ok(WhitelistCategory::DEX),
        "Lending" => Ok(WhitelistCategory::Lending),
        "Bridge" => Ok(WhitelistCategory::Bridge),
        other => Err(format!(
            "unknown whitelist category '{}': expected FlashLoan/DEX/Lending/Bridge",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_address_valid() {
        let addr =
            parse_hex_address("0xBA12222222228d8Ba445958a75a0704d566BF2C8").expect("valid hex");
        assert_eq!(
            format!("{addr:?}"),
            format!(
                "{:?}",
                Address::from_slice(
                    &hex::decode("BA12222222228d8Ba445958a75a0704d566BF2C8").unwrap()
                )
            )
        );
    }

    #[test]
    fn parse_hex_address_no_prefix() {
        let addr =
            parse_hex_address("BA12222222228d8Ba445958a75a0704d566BF2C8").expect("valid hex");
        assert_eq!(
            addr,
            Address::from_slice(&hex::decode("BA12222222228d8Ba445958a75a0704d566BF2C8").unwrap())
        );
    }

    #[test]
    fn parse_hex_address_invalid_hex() {
        assert!(parse_hex_address("0xZZZZZZ").is_err());
    }

    #[test]
    fn parse_hex_address_wrong_length() {
        assert!(parse_hex_address("0xDEAD").is_err());
    }

    #[test]
    fn parse_whitelist_category_all_variants() {
        assert!(matches!(
            parse_whitelist_category("FlashLoan"),
            Ok(WhitelistCategory::FlashLoan)
        ));
        assert!(matches!(
            parse_whitelist_category("DEX"),
            Ok(WhitelistCategory::DEX)
        ));
        assert!(matches!(
            parse_whitelist_category("Dex"),
            Ok(WhitelistCategory::DEX)
        ));
        assert!(matches!(
            parse_whitelist_category("Lending"),
            Ok(WhitelistCategory::Lending)
        ));
        assert!(matches!(
            parse_whitelist_category("Bridge"),
            Ok(WhitelistCategory::Bridge)
        ));
    }

    #[test]
    fn parse_whitelist_category_unknown() {
        assert!(parse_whitelist_category("Unknown").is_err());
    }

    #[test]
    fn to_whitelist_entry_valid() {
        let toml_entry = WhitelistEntryToml {
            address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
            protocol: "Balancer Vault".to_string(),
            category: "FlashLoan".to_string(),
            score_modifier: -0.4,
        };
        let entry = toml_entry.to_whitelist_entry().expect("valid entry");
        assert_eq!(entry.protocol, "Balancer Vault");
        assert!(matches!(entry.category, WhitelistCategory::FlashLoan));
        assert!((entry.score_modifier - (-0.4)).abs() < f64::EPSILON);
    }

    #[test]
    fn to_whitelist_entry_rejects_positive_modifier() {
        let toml_entry = WhitelistEntryToml {
            address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
            protocol: "Bad".to_string(),
            category: "DEX".to_string(),
            score_modifier: 0.5,
        };
        assert!(toml_entry.to_whitelist_entry().is_err());
    }

    #[test]
    fn to_whitelist_entry_rejects_invalid_address() {
        let toml_entry = WhitelistEntryToml {
            address: "not-hex".to_string(),
            protocol: "Bad".to_string(),
            category: "DEX".to_string(),
            score_modifier: -0.1,
        };
        assert!(toml_entry.to_whitelist_entry().is_err());
    }

    #[test]
    fn to_whitelist_entry_rejects_unknown_category() {
        let toml_entry = WhitelistEntryToml {
            address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
            protocol: "Test".to_string(),
            category: "Staking".to_string(),
            score_modifier: -0.1,
        };
        assert!(toml_entry.to_whitelist_entry().is_err());
    }

    // -----------------------------------------------------------------------
    // Integration tests (SentinelFullConfig + whitelist TOML)
    // -----------------------------------------------------------------------

    use super::super::config::SentinelFullConfig;

    /// TOML wrapper matching the file-level `[sentinel]` table.
    #[derive(Debug, serde::Deserialize)]
    struct TomlWrapper {
        sentinel: Option<SentinelFullConfig>,
    }

    #[test]
    fn default_whitelist_is_empty() {
        let config = SentinelFullConfig::default();
        assert!(config.whitelist.entries.is_empty());
        let engine = config.to_whitelist_engine();
        assert!(engine.is_empty());
    }

    #[test]
    fn whitelist_toml_deserialization() {
        let toml_str = r#"
[sentinel]
enabled = true

[[sentinel.whitelist.entries]]
address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"
protocol = "Balancer Vault"
category = "FlashLoan"
score_modifier = -0.4

[[sentinel.whitelist.entries]]
address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
protocol = "Aave V3 Pool"
category = "Lending"
score_modifier = -0.35
"#;

        let wrapper: TomlWrapper = toml::from_str(toml_str).expect("parse");
        let config = wrapper.sentinel.expect("sentinel section");

        assert_eq!(config.whitelist.entries.len(), 2);

        let balancer = &config.whitelist.entries[0];
        assert_eq!(balancer.protocol, "Balancer Vault");
        assert_eq!(balancer.category, "FlashLoan");
        assert!((balancer.score_modifier - (-0.4)).abs() < f64::EPSILON);

        let aave = &config.whitelist.entries[1];
        assert_eq!(aave.category, "Lending");
        assert!((aave.score_modifier - (-0.35)).abs() < f64::EPSILON);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn whitelist_toml_inline_table_format() {
        let toml_str = r#"
[sentinel]
enabled = true

[sentinel.whitelist]
entries = [
    { address = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", protocol = "Uniswap SwapRouter02", category = "DEX", score_modifier = -0.3 },
]
"#;

        let wrapper: TomlWrapper = toml::from_str(toml_str).expect("parse");
        let config = wrapper.sentinel.expect("sentinel section");

        assert_eq!(config.whitelist.entries.len(), 1);
        assert_eq!(config.whitelist.entries[0].category, "DEX");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn whitelist_missing_section_defaults_to_empty() {
        let toml_str = r#"
[sentinel]
enabled = true

[sentinel.prefilter]
suspicion_threshold = 0.5
"#;

        let wrapper: TomlWrapper = toml::from_str(toml_str).expect("parse");
        let config = wrapper.sentinel.expect("sentinel section");

        assert!(config.whitelist.entries.is_empty());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_positive_score_modifier_whitelist() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    protocol: "Bad".to_string(),
                    category: "DEX".to_string(),
                    score_modifier: 0.5,
                }],
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("score_modifier"));
    }

    #[test]
    fn validate_rejects_empty_address_whitelist() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: String::new(),
                    protocol: "Test".to_string(),
                    category: "Bridge".to_string(),
                    score_modifier: -0.2,
                }],
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("address"));
    }

    #[test]
    fn validate_rejects_empty_protocol_whitelist() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    protocol: String::new(),
                    category: "Lending".to_string(),
                    score_modifier: -0.1,
                }],
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("protocol"));
    }

    #[test]
    fn validate_rejects_unknown_category() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0x0000000000000000000000000000000000000001".to_string(),
                    protocol: "Test".to_string(),
                    category: "Unknown".to_string(),
                    score_modifier: -0.1,
                }],
            },
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.contains("category"));
    }

    #[test]
    fn whitelist_roundtrip_serialization() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
                    protocol: "Balancer Vault".to_string(),
                    category: "FlashLoan".to_string(),
                    score_modifier: -0.4,
                }],
            },
            ..Default::default()
        };

        let serialized = toml::to_string(&config).expect("serialize");
        let deserialized: SentinelFullConfig = toml::from_str(&serialized).expect("deserialize");

        assert_eq!(deserialized.whitelist.entries.len(), 1);
        assert_eq!(
            deserialized.whitelist.entries[0].address,
            "0xBA12222222228d8Ba445958a75a0704d566BF2C8"
        );
        assert_eq!(deserialized.whitelist.entries[0].protocol, "Balancer Vault");
        assert_eq!(deserialized.whitelist.entries[0].category, "FlashLoan");
    }

    #[test]
    fn all_whitelist_categories_validate() {
        for cat in ["FlashLoan", "DEX", "Lending", "Bridge"] {
            let config = SentinelFullConfig {
                whitelist: WhitelistTomlConfig {
                    entries: vec![WhitelistEntryToml {
                        address: "0x0000000000000000000000000000000000000001".to_string(),
                        protocol: "Test".to_string(),
                        category: cat.to_string(),
                        score_modifier: -0.1,
                    }],
                },
                ..Default::default()
            };
            assert!(
                config.validate().is_ok(),
                "category '{}' should validate",
                cat
            );
        }
    }

    #[test]
    fn to_whitelist_engine_converts_valid_entries() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![
                    WhitelistEntryToml {
                        address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
                        protocol: "Balancer Vault".to_string(),
                        category: "FlashLoan".to_string(),
                        score_modifier: -0.4,
                    },
                    WhitelistEntryToml {
                        address: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".to_string(),
                        protocol: "Uniswap SwapRouter02".to_string(),
                        category: "DEX".to_string(),
                        score_modifier: -0.3,
                    },
                ],
            },
            ..Default::default()
        };

        let engine = config.to_whitelist_engine();
        assert_eq!(engine.len(), 2);
        assert!(!engine.is_empty());
    }

    #[test]
    fn to_whitelist_engine_skips_invalid_address() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![
                    WhitelistEntryToml {
                        address: "not-hex".to_string(),
                        protocol: "Bad".to_string(),
                        category: "DEX".to_string(),
                        score_modifier: -0.1,
                    },
                    WhitelistEntryToml {
                        address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
                        protocol: "Balancer Vault".to_string(),
                        category: "FlashLoan".to_string(),
                        score_modifier: -0.4,
                    },
                ],
            },
            ..Default::default()
        };

        let engine = config.to_whitelist_engine();
        assert_eq!(engine.len(), 1);
    }

    #[test]
    fn to_whitelist_engine_empty_config_gives_empty_engine() {
        let config = SentinelFullConfig::default();
        let engine = config.to_whitelist_engine();
        assert!(engine.is_empty());
    }

    #[test]
    fn to_whitelist_engine_rejects_positive_score_modifier() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0xBA12222222228d8Ba445958a75a0704d566BF2C8".to_string(),
                    protocol: "Bad Modifier".to_string(),
                    category: "FlashLoan".to_string(),
                    score_modifier: 0.5,
                }],
            },
            ..Default::default()
        };

        let engine = config.to_whitelist_engine();
        assert!(
            engine.is_empty(),
            "Positive score_modifier entry should be skipped"
        );
    }

    #[test]
    fn validate_accepts_dex_lowercase_variant() {
        let config = SentinelFullConfig {
            whitelist: WhitelistTomlConfig {
                entries: vec![WhitelistEntryToml {
                    address: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45".to_string(),
                    protocol: "Uniswap".to_string(),
                    category: "Dex".to_string(),
                    score_modifier: -0.3,
                }],
            },
            ..Default::default()
        };
        assert!(
            config.validate().is_ok(),
            "'Dex' should be accepted by validate()"
        );
    }
}
