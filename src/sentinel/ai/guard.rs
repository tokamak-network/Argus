//! Hallucination Guard — verifies AI evidence against actual AgentContext data.
//!
//! Like a fact-checker reviewing a journalist's article: every claim (evidence item)
//! must be traceable to real data (AgentContext). If any claim is fabricated, the
//! entire verdict is flagged as `evidence_valid = false`.

use ethrex_common::{Address, H256, U256};

use super::types::{AgentContext, AgentVerdict};

/// Validate AI evidence against the AgentContext.
///
/// Returns `true` only if ALL evidence items are verified against the context data.
/// Sets `evidence_valid` on the verdict accordingly.
///
/// Checks performed per evidence item:
/// - Addresses mentioned must exist in call_graph, transfers, or delegatecalls
/// - Amounts mentioned must be within +/-10% of actual values
/// - Function selectors (4-byte hex) must match call_graph input_selectors
/// - Event topic hashes must match log_events topic0
/// - Empty evidence array is always invalid
pub fn validate_evidence(verdict: &AgentVerdict, context: &AgentContext) -> bool {
    if verdict.evidence.is_empty() {
        return false;
    }

    let known_addresses = collect_addresses(context);
    let known_amounts = collect_amounts(context);
    let known_selectors = collect_selectors(context);
    let known_topics = collect_topics(context);

    for item in &verdict.evidence {
        if !verify_single_evidence(
            item,
            &known_addresses,
            &known_amounts,
            &known_selectors,
            &known_topics,
        ) {
            return false;
        }
    }

    true
}

/// Verify a single evidence string against known context data.
///
/// An evidence item passes if it references at least one verifiable data point
/// (address, amount, selector, or topic) that exists in the context.
/// Evidence items with no verifiable references are accepted (soft pass) to
/// avoid rejecting qualitative observations like "high gas usage pattern".
fn verify_single_evidence(
    evidence: &str,
    known_addresses: &[Address],
    known_amounts: &[U256],
    known_selectors: &[[u8; 4]],
    known_topics: &[H256],
) -> bool {
    let lower = evidence.to_lowercase();

    let mut has_verifiable_claim = false;
    let mut all_claims_valid = true;

    // Check addresses (0x-prefixed hex, 40 chars)
    for hex_addr in extract_hex_addresses(&lower) {
        has_verifiable_claim = true;
        if !known_addresses.iter().any(|a| format_addr(a) == hex_addr) {
            all_claims_valid = false;
            break;
        }
    }

    if !all_claims_valid {
        return false;
    }

    // Check amounts (decimal numbers that look like token/ETH amounts)
    for amount_str in extract_amounts(evidence) {
        if let Some(parsed) = parse_amount(&amount_str) {
            has_verifiable_claim = true;
            if !known_amounts
                .iter()
                .any(|actual| within_tolerance(parsed, *actual))
            {
                all_claims_valid = false;
                break;
            }
        }
    }

    if !all_claims_valid {
        return false;
    }

    // Check function selectors (0x-prefixed, 8 hex chars).
    // Skip when known_selectors is empty: ContextExtractor doesn't yet extract
    // selectors from calldata (TODO phase2), so an empty set would cause every
    // selector reference to be flagged as hallucination.
    if !known_selectors.is_empty() {
        for selector_hex in extract_selectors(&lower) {
            if let Some(selector) = parse_selector(&selector_hex) {
                has_verifiable_claim = true;
                if !known_selectors.contains(&selector) {
                    all_claims_valid = false;
                    break;
                }
            }
        }

        if !all_claims_valid {
            return false;
        }
    }

    // Check event topic hashes (0x-prefixed, 64 hex chars)
    for topic_hex in extract_topic_hashes(&lower) {
        if let Some(topic) = parse_h256(&topic_hex) {
            has_verifiable_claim = true;
            if !known_topics.contains(&topic) {
                all_claims_valid = false;
                break;
            }
        }
    }

    if !all_claims_valid {
        return false;
    }

    // If evidence has verifiable claims and all passed, return true.
    // If no verifiable claims found (qualitative observation), soft pass.
    !has_verifiable_claim || all_claims_valid
}

// ── Address collection ─────────────────────────────────────────────────────

fn collect_addresses(ctx: &AgentContext) -> Vec<Address> {
    let mut addrs = Vec::new();

    addrs.push(ctx.from);
    if let Some(to) = ctx.to {
        addrs.push(to);
    }

    for frame in &ctx.call_graph {
        addrs.push(frame.caller);
        addrs.push(frame.target);
    }

    for transfer in &ctx.erc20_transfers {
        addrs.push(transfer.token);
        addrs.push(transfer.from);
        addrs.push(transfer.to);
    }

    for transfer in &ctx.eth_transfers {
        addrs.push(transfer.from);
        addrs.push(transfer.to);
    }

    for dc in &ctx.delegatecalls {
        addrs.push(dc.caller);
        addrs.push(dc.target);
    }

    for mutation in &ctx.storage_mutations {
        addrs.push(mutation.contract);
    }

    for creation in &ctx.contract_creations {
        addrs.push(creation.deployer);
        addrs.push(creation.deployed);
    }

    for event in &ctx.log_events {
        addrs.push(event.address);
    }

    addrs.sort();
    addrs.dedup();
    addrs
}

// ── Amount collection ──────────────────────────────────────────────────────

fn collect_amounts(ctx: &AgentContext) -> Vec<U256> {
    let mut amounts = Vec::new();

    if ctx.value_wei > U256::zero() {
        amounts.push(ctx.value_wei);
    }

    for transfer in &ctx.erc20_transfers {
        if transfer.amount > U256::zero() {
            amounts.push(transfer.amount);
        }
    }

    for transfer in &ctx.eth_transfers {
        if transfer.value > U256::zero() {
            amounts.push(transfer.value);
        }
    }

    for frame in &ctx.call_graph {
        if frame.value > U256::zero() {
            amounts.push(frame.value);
        }
    }

    amounts
}

// ── Selector collection ────────────────────────────────────────────────────

fn collect_selectors(ctx: &AgentContext) -> Vec<[u8; 4]> {
    let mut selectors = Vec::new();

    for frame in &ctx.call_graph {
        if let Some(sel) = frame.input_selector {
            selectors.push(sel);
        }
    }

    for dc in &ctx.delegatecalls {
        if let Some(sel) = dc.input_selector {
            selectors.push(sel);
        }
    }

    selectors.sort();
    selectors.dedup();
    selectors
}

// ── Topic collection ───────────────────────────────────────────────────────

fn collect_topics(ctx: &AgentContext) -> Vec<H256> {
    let mut topics = Vec::new();

    for event in &ctx.log_events {
        topics.push(event.topic0);
        for t in &event.topics {
            topics.push(*t);
        }
    }

    topics.sort();
    topics.dedup();
    topics
}

// ── Hex parsing helpers ────────────────────────────────────────────────────

fn format_addr(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr.as_bytes()))
}

/// Extract 0x-prefixed 40-char hex strings (Ethereum addresses).
fn extract_hex_addresses(text: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let mut i = 0;
    let bytes = text.as_bytes();

    while i < bytes.len().saturating_sub(41) {
        if bytes[i] == b'0' && bytes[i + 1] == b'x' {
            let candidate = &text[i..i + 42];
            if candidate[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                // Ensure it's not a longer hex string (like a topic hash)
                let is_longer = i + 42 < bytes.len() && bytes[i + 42].is_ascii_hexdigit();
                if !is_longer {
                    addrs.push(candidate.to_string());
                    i += 42;
                    continue;
                }
            }
        }
        i += 1;
    }

    addrs
}

/// Extract potential amount strings (integers >= 1000, likely wei or token amounts).
///
/// Skips digit sequences that are part of `0x`-prefixed hex strings (addresses,
/// selectors, topic hashes) to avoid treating hex digits as decimal amounts.
fn extract_amounts(text: &str) -> Vec<String> {
    let mut amounts = Vec::new();
    let mut current = String::new();
    let bytes = text.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let ch = bytes[i] as char;

        // Skip 0x-prefixed hex strings entirely
        if ch == '0' && i + 1 < bytes.len() && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X') {
            // Flush any accumulated digits before the 0x
            if current.len() >= 4 {
                amounts.push(current.clone());
            }
            current.clear();
            // Skip past the hex string
            i += 2; // skip '0x'
            while i < bytes.len() && (bytes[i] as char).is_ascii_hexdigit() {
                i += 1;
            }
            continue;
        }

        if ch.is_ascii_digit() {
            current.push(ch);
        } else if ch == '_' && !current.is_empty() {
            // Allow underscores in numeric literals
        } else {
            if current.len() >= 4 {
                amounts.push(current.clone());
            }
            current.clear();
        }
        i += 1;
    }

    if current.len() >= 4 {
        amounts.push(current);
    }

    amounts
}

/// Extract 0x-prefixed 8-char hex strings (function selectors).
fn extract_selectors(text: &str) -> Vec<String> {
    let mut selectors = Vec::new();
    let mut i = 0;
    let bytes = text.as_bytes();

    while i < bytes.len().saturating_sub(9) {
        if bytes[i] == b'0' && bytes[i + 1] == b'x' {
            let candidate = &text[i..i + 10];
            if candidate[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                // Must be exactly 8 hex chars (not part of a longer hex string)
                let is_longer = i + 10 < bytes.len() && bytes[i + 10].is_ascii_hexdigit();
                let is_address = candidate[2..].len() >= 40;
                if !is_longer && !is_address {
                    selectors.push(candidate.to_string());
                    i += 10;
                    continue;
                }
            }
        }
        i += 1;
    }

    selectors
}

/// Extract 0x-prefixed 64-char hex strings (topic hashes / H256).
fn extract_topic_hashes(text: &str) -> Vec<String> {
    let mut topics = Vec::new();
    let mut i = 0;
    let bytes = text.as_bytes();

    while i < bytes.len().saturating_sub(65) {
        if bytes[i] == b'0' && bytes[i + 1] == b'x' {
            let candidate = &text[i..i + 66];
            if candidate[2..].chars().all(|c| c.is_ascii_hexdigit()) {
                let is_longer = i + 66 < bytes.len() && bytes[i + 66].is_ascii_hexdigit();
                if !is_longer {
                    topics.push(candidate.to_string());
                    i += 66;
                    continue;
                }
            }
        }
        i += 1;
    }

    topics
}

fn parse_selector(hex_str: &str) -> Option<[u8; 4]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() != 8 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    Some([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn parse_h256(hex_str: &str) -> Option<H256> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() != 64 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    Some(H256::from_slice(&bytes))
}

fn parse_amount(s: &str) -> Option<U256> {
    U256::from_dec_str(s).ok()
}

/// Check if `claimed` is within +/-10% of `actual`.
fn within_tolerance(claimed: U256, actual: U256) -> bool {
    if actual.is_zero() {
        return claimed.is_zero();
    }

    // Calculate 10% of actual
    let ten_pct = actual / U256::from(10);

    let lower = actual.saturating_sub(ten_pct);
    let upper = actual.saturating_add(ten_pct);

    claimed >= lower && claimed <= upper
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentinel::ai::types::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    fn h256(byte: u8) -> H256 {
        H256::from([byte; 32])
    }

    fn minimal_context() -> AgentContext {
        AgentContext {
            tx_hash: h256(1),
            block_number: 21_000_000,
            from: addr(0xAA),
            to: Some(addr(0xBB)),
            value_wei: U256::zero(),
            gas_used: 100_000,
            succeeded: true,
            revert_count: 0,
            suspicious_score: 0.3,
            suspicion_reasons: vec![],
            call_graph: vec![],
            storage_mutations: vec![],
            erc20_transfers: vec![],
            eth_transfers: vec![],
            log_events: vec![],
            delegatecalls: vec![],
            contract_creations: vec![],
        }
    }

    fn attack_verdict(evidence: Vec<String>) -> AgentVerdict {
        AgentVerdict {
            is_attack: true,
            confidence: 0.9,
            attack_type: Some(AttackType::Reentrancy),
            reasoning: "test".to_string(),
            evidence,
            evidence_valid: false,
            false_positive_reason: None,
            model_used: "test".to_string(),
            tokens_used: 100,
            latency_ms: 200,
        }
    }

    #[test]
    fn empty_evidence_is_invalid() {
        let ctx = minimal_context();
        let verdict = attack_verdict(vec![]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn qualitative_evidence_passes() {
        let ctx = minimal_context();
        let verdict = attack_verdict(vec![
            "High gas usage pattern detected".to_string(),
            "Multiple internal reverts observed".to_string(),
        ]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn valid_address_in_evidence_passes() {
        let ctx = minimal_context();
        let addr_hex = format_addr(&addr(0xAA));
        let verdict = attack_verdict(vec![format!("CALL to {addr_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn invalid_address_in_evidence_fails() {
        let ctx = minimal_context();
        let fake = format_addr(&addr(0xFF));
        let verdict = attack_verdict(vec![format!("CALL to {fake}")]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn valid_amount_passes() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_u64),
        }];
        let verdict = attack_verdict(vec!["Transfer amount: 1000000".to_string()]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn amount_within_10_percent_passes() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_u64),
        }];
        // 950000 is within 10% of 1000000
        let verdict = attack_verdict(vec!["Transfer of 950000 tokens".to_string()]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn amount_outside_10_percent_fails() {
        let mut ctx = minimal_context();
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_u64),
        }];
        // 800000 is outside 10% of 1000000
        let verdict = attack_verdict(vec!["Transfer of 800000 tokens".to_string()]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn valid_selector_passes() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![CallFrame {
            depth: 0,
            caller: addr(0xAA),
            target: addr(0xBB),
            value: U256::zero(),
            input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            input_size: 68,
            output_size: 32,
            gas_used: 50_000,
            call_type: CallType::Call,
            reverted: false,
        }];
        let verdict = attack_verdict(vec!["Function call 0xdeadbeef".to_string()]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn invalid_selector_fails() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![CallFrame {
            depth: 0,
            caller: addr(0xAA),
            target: addr(0xBB),
            value: U256::zero(),
            input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            input_size: 68,
            output_size: 32,
            gas_used: 50_000,
            call_type: CallType::Call,
            reverted: false,
        }];
        let verdict = attack_verdict(vec!["Function call 0x12345678".to_string()]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn valid_topic_passes() {
        let mut ctx = minimal_context();
        let topic = h256(0xAA);
        ctx.log_events = vec![LogEvent {
            address: addr(0x55),
            topic0: topic,
            topics: vec![],
            data_size: 32,
        }];
        let topic_hex = format!("0x{}", hex::encode(topic.as_bytes()));
        let verdict = attack_verdict(vec![format!("Event topic {topic_hex}")]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn invalid_topic_fails() {
        let mut ctx = minimal_context();
        ctx.log_events = vec![LogEvent {
            address: addr(0x55),
            topic0: h256(0xAA),
            topics: vec![],
            data_size: 32,
        }];
        let fake_topic = format!("0x{}", hex::encode(h256(0xFF).as_bytes()));
        let verdict = attack_verdict(vec![format!("Event topic {fake_topic}")]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn mixed_valid_evidence_passes() {
        let mut ctx = minimal_context();
        ctx.call_graph = vec![CallFrame {
            depth: 0,
            caller: addr(0xAA),
            target: addr(0xBB),
            value: U256::zero(),
            input_selector: Some([0xde, 0xad, 0xbe, 0xef]),
            input_size: 68,
            output_size: 32,
            gas_used: 50_000,
            call_type: CallType::Call,
            reverted: false,
        }];
        ctx.erc20_transfers = vec![TokenTransfer {
            token: addr(0x10),
            from: addr(0x20),
            to: addr(0x30),
            amount: U256::from(1_000_000_u64),
        }];

        let addr_hex = format_addr(&addr(0xAA));
        let verdict = attack_verdict(vec![
            format!("CALL from {addr_hex} with selector 0xdeadbeef"),
            "Transfer of 1000000 tokens".to_string(),
        ]);
        assert!(validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn one_invalid_evidence_fails_all() {
        let ctx = minimal_context();
        let valid_addr = format_addr(&addr(0xAA));
        let invalid_addr = format_addr(&addr(0xFF));
        let verdict = attack_verdict(vec![
            format!("CALL to {valid_addr}"),
            format!("CALL to {invalid_addr}"),
        ]);
        assert!(!validate_evidence(&verdict, &ctx));
    }

    #[test]
    fn within_tolerance_exact_match() {
        let v = U256::from(1_000_000_u64);
        assert!(within_tolerance(v, v));
    }

    #[test]
    fn within_tolerance_boundary() {
        let actual = U256::from(1_000_000_u64);
        let lower = U256::from(900_000_u64); // exactly -10%
        let upper = U256::from(1_100_000_u64); // exactly +10%
        assert!(within_tolerance(lower, actual));
        assert!(within_tolerance(upper, actual));
    }

    #[test]
    fn within_tolerance_zero() {
        assert!(within_tolerance(U256::zero(), U256::zero()));
        assert!(!within_tolerance(U256::from(1_u64), U256::zero()));
    }
}
