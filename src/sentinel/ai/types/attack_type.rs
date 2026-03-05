//! Attack classification and EVM instruction type enums.

use serde::{Deserialize, Serialize};

// ── AttackType ──────────────────────────────────────────────────────────────

/// Attack classification returned by the AI agent.
///
/// LLM output is mapped to this enum. Unmapped strings fall back to `Other(raw)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "detail")]
pub enum AttackType {
    Reentrancy,
    FlashLoan,
    PriceManipulation,
    AccessControl,
    FrontRunning,
    Sandwich,
    /// Catch-all for attack types not yet classified.
    Other(String),
}

impl AttackType {
    /// Parse a raw string (LLM output) into an AttackType.
    /// Matching is case-insensitive. Unknown strings become `Other(s)`.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "reentrancy" => Self::Reentrancy,
            "flashloan" | "flash_loan" | "flash loan" => Self::FlashLoan,
            "pricemanipulation" | "price_manipulation" | "price manipulation" => {
                Self::PriceManipulation
            }
            "accesscontrol" | "access_control" | "access control" => Self::AccessControl,
            "frontrunning" | "front_running" | "front running" => Self::FrontRunning,
            "sandwich" => Self::Sandwich,
            other => Self::Other(other.to_string()),
        }
    }
}

// ── CallType / CreateType ────────────────────────────────────────────────────

/// EVM call instruction variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallType {
    Call,
    StaticCall,
    DelegateCall,
    CallCode,
}

/// EVM contract creation instruction variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreateType {
    Create,
    Create2,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_type_known_variants_roundtrip() {
        let cases = [
            ("reentrancy", AttackType::Reentrancy),
            ("flashloan", AttackType::FlashLoan),
            ("flash_loan", AttackType::FlashLoan),
            ("flash loan", AttackType::FlashLoan),
            ("pricemanipulation", AttackType::PriceManipulation),
            ("price_manipulation", AttackType::PriceManipulation),
            ("accesscontrol", AttackType::AccessControl),
            ("access_control", AttackType::AccessControl),
            ("frontrunning", AttackType::FrontRunning),
            ("front_running", AttackType::FrontRunning),
            ("sandwich", AttackType::Sandwich),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                AttackType::from_str_lossy(input),
                *expected,
                "failed for input: {input}"
            );
        }
    }

    #[test]
    fn attack_type_case_insensitive() {
        assert_eq!(
            AttackType::from_str_lossy("REENTRANCY"),
            AttackType::Reentrancy
        );
        assert_eq!(
            AttackType::from_str_lossy("FlashLoan"),
            AttackType::FlashLoan
        );
    }

    #[test]
    fn attack_type_unknown_becomes_other() {
        let result = AttackType::from_str_lossy("governance takeover");
        assert!(matches!(result, AttackType::Other(_)));
        if let AttackType::Other(s) = result {
            assert_eq!(s, "governance takeover");
        }
    }

    #[test]
    fn attack_type_json_roundtrip() {
        let variants: Vec<AttackType> = vec![
            AttackType::Reentrancy,
            AttackType::FlashLoan,
            AttackType::PriceManipulation,
            AttackType::AccessControl,
            AttackType::FrontRunning,
            AttackType::Sandwich,
            AttackType::Other("custom attack".to_string()),
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let decoded: AttackType = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, variant);
        }
    }
}
