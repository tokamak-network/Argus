//! Display formatting for debugger output.

use std::collections::BTreeSet;

use ethrex_common::U256;
use ethrex_levm::opcodes::Opcode;

use crate::types::{ReplayTrace, StepRecord};

/// Format a step for detailed display (after step/goto).
pub fn format_step(step: &StepRecord, total: usize) -> String {
    let name = opcode_name(step.opcode);
    let stack_preview = format_stack_inline(&step.stack_top);
    format!(
        "[{}/{}] PC={:#06x}  {:<14} depth={}  gas={}\n  stack({}): [{}]",
        step.step_index,
        total,
        step.pc,
        name,
        step.depth,
        step.gas_remaining,
        step.stack_depth,
        stack_preview,
    )
}

/// Format a step compactly (for list view).
pub fn format_step_compact(step: &StepRecord, total: usize, is_cursor: bool) -> String {
    let marker = if is_cursor { ">" } else { " " };
    format!(
        "{marker} [{}/{}] PC={:#06x}  {:<14} depth={}  gas={}",
        step.step_index,
        total,
        step.pc,
        opcode_name(step.opcode),
        step.depth,
        step.gas_remaining,
    )
}

/// Format trace info summary.
pub fn format_info(trace: &ReplayTrace, position: usize) -> String {
    let output_hex = if trace.output.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(&trace.output))
    };
    format!(
        "Trace: {} steps | gas_used: {} | success: {} | output: {}\nPosition: {}/{}",
        trace.steps.len(),
        trace.gas_used,
        trace.success,
        output_hex,
        position,
        trace.steps.len(),
    )
}

/// Format the full stack of a step.
pub fn format_stack(step: &StepRecord) -> String {
    if step.stack_top.is_empty() {
        return format!("Stack depth: {} (empty)", step.stack_depth);
    }
    let mut lines = vec![format!(
        "Stack depth: {} (showing top {}):",
        step.stack_depth,
        step.stack_top.len()
    )];
    for (i, val) in step.stack_top.iter().enumerate() {
        lines.push(format!("  [{}]: {:#x}", i, val));
    }
    lines.join("\n")
}

/// Format the list of active breakpoints.
pub fn format_breakpoints(breakpoints: &BTreeSet<usize>) -> String {
    if breakpoints.is_empty() {
        return "No breakpoints set.".to_string();
    }
    let mut lines = vec![format!("Breakpoints ({}):", breakpoints.len())];
    for pc in breakpoints {
        lines.push(format!("  PC={:#06x} ({})", pc, pc));
    }
    lines.join("\n")
}

/// Static help text.
pub fn format_help() -> String {
    "\
Commands:
  s, step            Step forward one opcode
  sb, step-back      Step backward one opcode
  c, continue        Continue until breakpoint or end
  rc, reverse-continue  Continue backward until breakpoint or start
  b, break <pc>      Set breakpoint at PC (hex 0x0a or decimal 10)
  d, delete <pc>     Delete breakpoint at PC
  g, goto <step>     Jump to step number
  i, info            Show trace summary
  st, stack          Show current stack
  l, list [n]        List n steps around cursor (default: 5)
  bp, breakpoints    List all breakpoints
  h, help            Show this help
  q, quit            Exit debugger"
        .to_string()
}

/// Convert an opcode byte to its human-readable name.
pub fn opcode_name(byte: u8) -> String {
    format!("{:?}", Opcode::from(byte))
}

fn format_stack_inline(stack_top: &[U256]) -> String {
    stack_top
        .iter()
        .map(|v| format!("{:#x}", v))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format the full autopsy analysis result as a terminal report.
///
/// Produces a box-drawing bordered report with transaction metadata,
/// detected attack patterns, fund flow summary, and overall risk level.
#[cfg(feature = "autopsy")]
pub fn format_autopsy_summary(
    patterns: &[crate::autopsy::types::AttackPattern],
    flows: &[crate::autopsy::types::FundFlow],
    trace: &ReplayTrace,
    tx_hash: &str,
    block_number: u64,
) -> String {
    const WIDE: &str = "═══════════════════════════════════════════";
    const THIN: &str = "───────────────────────────────────────────";

    // Truncate tx hash for display: first 10 + last 4 chars
    let tx_display = if tx_hash.len() > 14 {
        format!("{}...{}", &tx_hash[..10], &tx_hash[tx_hash.len() - 4..])
    } else {
        tx_hash.to_string()
    };

    let status = if trace.success { "Success" } else { "Reverted" };
    let steps_formatted = format_number_with_commas(trace.steps.len() as u64);
    let gas_formatted = format_number_with_commas(trace.gas_used);

    // Build pattern section
    let pattern_section = if patterns.is_empty() {
        "  No attack patterns detected\n".to_string()
    } else {
        let mut lines = format!("  Attack Patterns: {}\n", patterns.len());
        for p in patterns {
            lines.push_str(&format!("    - {}\n", format_attack_pattern(p)));
        }
        lines
    };

    // Build fund flow section
    let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
    let erc20_flows: Vec<_> = flows.iter().filter(|f| f.token.is_some()).collect();

    let flow_section = if flows.is_empty() {
        "  No fund flows detected\n".to_string()
    } else {
        let mut lines = format!("  Fund Flows: {} transfers\n", flows.len());
        if !eth_flows.is_empty() {
            let total_eth: ethrex_common::U256 = eth_flows
                .iter()
                .fold(ethrex_common::U256::zero(), |acc, f| acc + f.value);
            lines.push_str(&format!(
                "    ETH:   {} transfer(s), total {}\n",
                eth_flows.len(),
                format_u256_eth(total_eth)
            ));
        }
        if !erc20_flows.is_empty() {
            lines.push_str(&format!(
                "    ERC20: {} transfer(s) detected\n",
                erc20_flows.len()
            ));
        }
        lines
    };

    // Risk level based on pattern severity
    let risk = compute_risk_level(patterns);

    format!(
        "{WIDE}\n  Argus Autopsy Report\n{WIDE}\n  TX:     {tx_display}\n  Block:  {block_number}\n  Steps:  {steps_formatted}\n  Gas:    {gas_formatted}\n  Status: {status}\n{THIN}\n{pattern_section}{THIN}\n{flow_section}{THIN}\n  Risk: {risk}\n{WIDE}"
    )
}

/// Format a single `AttackPattern` variant as a human-readable string.
#[cfg(feature = "autopsy")]
fn format_attack_pattern(pattern: &crate::autopsy::types::AttackPattern) -> String {
    use crate::autopsy::types::AttackPattern;
    match pattern {
        AttackPattern::Reentrancy {
            call_depth_at_entry,
            ..
        } => format!("Reentrancy (depth: {call_depth_at_entry})"),
        AttackPattern::FlashLoan { .. } => "FlashLoan (callback detected)".to_string(),
        AttackPattern::PriceManipulation {
            price_delta_percent,
            ..
        } => format!("PriceManipulation (delta: {price_delta_percent:.1}%)"),
        AttackPattern::AccessControlBypass { .. } => "AccessControlBypass".to_string(),
    }
}

/// Compute a risk label from the set of detected patterns.
#[cfg(feature = "autopsy")]
fn compute_risk_level(patterns: &[crate::autopsy::types::AttackPattern]) -> &'static str {
    use crate::autopsy::types::AttackPattern;
    if patterns.is_empty() {
        return "NONE";
    }
    let has_critical = patterns.iter().any(|p| {
        matches!(
            p,
            AttackPattern::Reentrancy { .. }
                | AttackPattern::FlashLoan { .. }
                | AttackPattern::AccessControlBypass { .. }
        )
    });
    if has_critical { "HIGH" } else { "MEDIUM" }
}

/// Format a u64 with comma separators (e.g., 1_200_000 → "1,200,000").
fn format_number_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Format a U256 Wei value as an ETH string (e.g., "150.0 ETH").
#[cfg(feature = "autopsy")]
fn format_u256_eth(wei: ethrex_common::U256) -> String {
    // 1 ETH = 10^18 wei; display as integer ETH for simplicity
    let eth_u256 = wei / ethrex_common::U256::from(10u64.pow(18));
    let remainder = wei % ethrex_common::U256::from(10u64.pow(18));
    if remainder.is_zero() {
        format!("{eth_u256} ETH")
    } else {
        format!("{eth_u256}.x ETH")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "autopsy")]
    use crate::autopsy::types::AttackPattern;
    use crate::types::{ReplayConfig, ReplayTrace};
    use bytes::Bytes;
    use ethrex_common::{Address, U256};

    fn make_trace(steps: usize, gas_used: u64, success: bool) -> ReplayTrace {
        ReplayTrace {
            steps: (0..steps)
                .map(|i| crate::types::StepRecord {
                    step_index: i,
                    pc: 0,
                    opcode: 0x00,
                    depth: 0,
                    gas_remaining: 1_000_000,
                    stack_top: vec![],
                    stack_depth: 0,
                    memory_size: 0,
                    code_address: Address::default(),
                    call_value: None,
                    storage_writes: None,
                    log_topics: None,
                    log_data: None,
                    call_input_selector: None,
                })
                .collect(),
            config: ReplayConfig::default(),
            gas_used,
            success,
            output: Bytes::new(),
        }
    }

    #[test]
    #[cfg(feature = "autopsy")]
    fn test_format_autopsy_summary_empty() {
        let trace = make_trace(0, 0, true);
        let result = format_autopsy_summary(&[], &[], &trace, "0xabcdef1234", 12345678);
        assert!(result.contains("No attack patterns detected"));
        assert!(result.contains("No fund flows detected"));
        assert!(result.contains("Risk: NONE"));
        assert!(result.contains("Block:  12345678"));
        assert!(result.contains("Status: Success"));
    }

    #[test]
    #[cfg(feature = "autopsy")]
    fn test_format_autopsy_summary_with_patterns() {
        let trace = make_trace(145_302, 1_200_000, true);
        let patterns = vec![
            AttackPattern::Reentrancy {
                target_contract: Address::default(),
                reentrant_call_step: 10,
                state_modified_step: 20,
                call_depth_at_entry: 3,
            },
            AttackPattern::FlashLoan {
                borrow_step: 5,
                borrow_amount: U256::from(1_000_000u64),
                repay_step: 100,
                repay_amount: U256::from(1_000_900u64),
                provider: None,
                token: None,
            },
        ];
        let result =
            format_autopsy_summary(&patterns, &[], &trace, "0x46deef0fabcdef007882", 21989247);
        assert!(result.contains("Attack Patterns: 2"));
        assert!(result.contains("Reentrancy (depth: 3)"));
        assert!(result.contains("FlashLoan (callback detected)"));
        assert!(result.contains("Risk: HIGH"));
        assert!(result.contains("Steps:  145,302"));
        assert!(result.contains("Gas:    1,200,000"));
        // tx hash truncated
        assert!(result.contains("0x46deef0f...7882"));
    }

    #[test]
    #[cfg(feature = "autopsy")]
    fn test_format_attack_pattern_variants() {
        let reentrancy = AttackPattern::Reentrancy {
            target_contract: Address::default(),
            reentrant_call_step: 1,
            state_modified_step: 2,
            call_depth_at_entry: 5,
        };
        assert_eq!(format_attack_pattern(&reentrancy), "Reentrancy (depth: 5)");

        let flash_loan = AttackPattern::FlashLoan {
            borrow_step: 1,
            borrow_amount: U256::zero(),
            repay_step: 2,
            repay_amount: U256::zero(),
            provider: None,
            token: None,
        };
        assert_eq!(
            format_attack_pattern(&flash_loan),
            "FlashLoan (callback detected)"
        );

        let price_manip = AttackPattern::PriceManipulation {
            oracle_read_before: 1,
            swap_step: 2,
            oracle_read_after: 3,
            price_delta_percent: 15.5,
        };
        assert_eq!(
            format_attack_pattern(&price_manip),
            "PriceManipulation (delta: 15.5%)"
        );

        let acl = AttackPattern::AccessControlBypass {
            sstore_step: 5,
            contract: Address::default(),
        };
        assert_eq!(format_attack_pattern(&acl), "AccessControlBypass");
    }

    #[test]
    fn test_format_number_with_commas() {
        assert_eq!(format_number_with_commas(0), "0");
        assert_eq!(format_number_with_commas(999), "999");
        assert_eq!(format_number_with_commas(1_000), "1,000");
        assert_eq!(format_number_with_commas(1_200_000), "1,200,000");
        assert_eq!(format_number_with_commas(145_302), "145,302");
    }
}
