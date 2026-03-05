//! AgentVerdict — AI judgement result for a single transaction.

use serde::{Deserialize, Serialize};

use super::attack_type::AttackType;

/// AI judgement result for a single transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentVerdict {
    pub is_attack: bool,
    /// Confidence 0.0 – 1.0.
    pub confidence: f64,
    pub attack_type: Option<AttackType>,
    /// Natural-language reasoning from the model.
    pub reasoning: String,
    /// Key evidence items cited by the model.
    pub evidence: Vec<String>,
    /// Hallucination Guard result: true if all evidence items verified against context.
    pub evidence_valid: bool,
    /// Why the model thinks this is a false positive (if applicable).
    pub false_positive_reason: Option<String>,
    /// Model identifier used (e.g. "claude-haiku-4-5-20251001").
    pub model_used: String,
    pub tokens_used: u32,
    pub latency_ms: u64,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_verdict(is_attack: bool) -> AgentVerdict {
        AgentVerdict {
            is_attack,
            confidence: if is_attack { 0.92 } else { 0.1 },
            attack_type: if is_attack {
                Some(AttackType::Reentrancy)
            } else {
                None
            },
            reasoning: "Multiple internal reverts detected at identical storage slots".to_string(),
            evidence: vec![
                "Revert count: 5".to_string(),
                "Storage slot 0x01 mutated 3 times".to_string(),
            ],
            evidence_valid: true,
            false_positive_reason: None,
            model_used: "claude-haiku-4-5-20251001".to_string(),
            tokens_used: 312,
            latency_ms: 450,
        }
    }

    #[test]
    fn agent_verdict_attack_roundtrip() {
        let verdict = sample_verdict(true);
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.is_attack);
        assert!((decoded.confidence - 0.92).abs() < f64::EPSILON);
        assert_eq!(decoded.attack_type, Some(AttackType::Reentrancy));
        assert!(decoded.evidence_valid);
        assert_eq!(decoded.tokens_used, 312);
    }

    #[test]
    fn agent_verdict_non_attack_roundtrip() {
        let verdict = sample_verdict(false);
        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(!decoded.is_attack);
        assert!(decoded.attack_type.is_none());
    }

    #[test]
    fn agent_verdict_with_false_positive_reason() {
        let mut verdict = sample_verdict(false);
        verdict.false_positive_reason =
            Some("Known DeFi protocol internal rebalancing".to_string());

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.false_positive_reason.is_some());
    }

    #[test]
    fn agent_verdict_empty_evidence_serializes() {
        let mut verdict = sample_verdict(false);
        verdict.evidence = vec![];
        verdict.evidence_valid = false;

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert!(decoded.evidence.is_empty());
        assert!(!decoded.evidence_valid);
    }

    #[test]
    fn agent_verdict_other_attack_type() {
        let mut verdict = sample_verdict(true);
        verdict.attack_type = Some(AttackType::Other("governance attack".to_string()));

        let json = serde_json::to_string(&verdict).unwrap();
        let decoded: AgentVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.attack_type,
            Some(AttackType::Other("governance attack".to_string()))
        );
    }
}
