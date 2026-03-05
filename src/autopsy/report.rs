//! Autopsy report generation (JSON + Markdown).

use ethrex_common::{Address, H256, U256};
use serde::Serialize;

use crate::types::{StepRecord, StorageWrite};

use super::labels::{
    format_addr, format_pattern_detail, interpret_value, known_label, opcode_name, pattern_name,
    truncate_slot,
};
use super::types::{AnnotatedStep, AttackPattern, FundFlow, Severity};

/// Execution statistics derived from the opcode trace.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionOverview {
    pub max_call_depth: usize,
    pub unique_contracts: usize,
    pub call_count: usize,
    pub sstore_count: usize,
    pub sload_count: usize,
    pub log_count: usize,
    pub create_count: usize,
    /// Top 5 most frequent opcode categories: (opcode_byte, name, count).
    /// PUSHn/DUPn/SWAPn are aggregated by category.
    pub top_opcodes: Vec<(u8, String, usize)>,
}

/// Complete autopsy report for a single transaction.
#[derive(Debug, Clone, Serialize)]
pub struct AutopsyReport {
    pub tx_hash: H256,
    pub block_number: u64,
    pub summary: String,
    pub execution_overview: ExecutionOverview,
    pub attack_patterns: Vec<AttackPattern>,
    pub fund_flows: Vec<FundFlow>,
    pub storage_diffs: Vec<StorageWrite>,
    pub total_steps: usize,
    pub key_steps: Vec<AnnotatedStep>,
    pub affected_contracts: Vec<Address>,
    pub suggested_fixes: Vec<String>,
}

impl AutopsyReport {
    /// Build a report from analysis results.
    pub fn build(
        tx_hash: H256,
        block_number: u64,
        steps: &[StepRecord],
        attack_patterns: Vec<AttackPattern>,
        fund_flows: Vec<FundFlow>,
        storage_diffs: Vec<StorageWrite>,
    ) -> Self {
        let total_steps = steps.len();
        let execution_overview = Self::compute_overview(steps);
        let key_steps = Self::identify_key_steps(&attack_patterns, &fund_flows, steps);
        let affected_contracts =
            Self::collect_affected_contracts(steps, &attack_patterns, &fund_flows, &storage_diffs);
        let suggested_fixes = Self::suggest_fixes(&attack_patterns);
        let summary = Self::generate_summary(&attack_patterns, &fund_flows, &execution_overview);

        Self {
            tx_hash,
            block_number,
            summary,
            execution_overview,
            attack_patterns,
            fund_flows,
            storage_diffs,
            total_steps,
            key_steps,
            affected_contracts,
            suggested_fixes,
        }
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Render as Markdown report.
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# Smart Contract Autopsy Report\n\n");
        md.push_str(&format!("**Transaction**: `0x{:x}`\n", self.tx_hash));
        md.push_str(&format!("**Block**: {}\n", self.block_number));
        md.push_str(&format!("**Total Steps**: {}\n\n", self.total_steps));

        // Summary (verdict-first)
        md.push_str("## Summary\n\n");
        md.push_str(&self.summary);
        md.push_str("\n\n");

        // Execution Overview
        md.push_str("## Execution Overview\n\n");
        let ov = &self.execution_overview;
        md.push_str("| Metric | Value |\n|---|---|\n");
        md.push_str(&format!("| Max call depth | {} |\n", ov.max_call_depth));
        md.push_str(&format!("| Unique contracts | {} |\n", ov.unique_contracts));
        md.push_str(&format!(
            "| CALL/STATICCALL/DELEGATECALL | {} |\n",
            ov.call_count
        ));
        md.push_str(&format!("| CREATE/CREATE2 | {} |\n", ov.create_count));
        md.push_str(&format!("| SLOAD | {} |\n", ov.sload_count));
        md.push_str(&format!("| SSTORE | {} |\n", ov.sstore_count));
        md.push_str(&format!("| LOG0-LOG4 | {} |\n\n", ov.log_count));

        if !ov.top_opcodes.is_empty() {
            md.push_str("**Top opcodes**: ");
            let parts: Vec<String> = ov
                .top_opcodes
                .iter()
                .map(|(_, name, count)| format!("{name}({count})"))
                .collect();
            md.push_str(&parts.join(", "));
            md.push_str("\n\n");
        }

        // Attack Patterns
        md.push_str("## Attack Patterns\n\n");
        if self.attack_patterns.is_empty() {
            md.push_str("No known attack patterns detected.\n\n");
        } else {
            md.push_str(&format!(
                "{} pattern(s) detected in this transaction.\n\n",
                self.attack_patterns.len()
            ));
            for (i, pattern) in self.attack_patterns.iter().enumerate() {
                md.push_str(&format!(
                    "### Pattern {} — {}\n\n",
                    i + 1,
                    pattern_name(pattern)
                ));
                md.push_str(&format_pattern_detail(pattern));
                md.push('\n');
            }
        }

        // Fund Flows (with context linking to attack patterns)
        md.push_str("## Fund Flow\n\n");
        if self.fund_flows.is_empty() {
            md.push_str("No fund transfers detected.\n\n");
        } else {
            if let Some(AttackPattern::FlashLoan {
                borrow_step,
                repay_step,
                ..
            }) = self.attack_patterns.first()
            {
                md.push_str(&format!(
                    "The following transfers occurred within the flash loan callback span (steps {}–{}).\n\n",
                    borrow_step, repay_step
                ));
            }
            md.push_str("| Step | From | To | Value | Token |\n");
            md.push_str("|---|---|---|---|---|\n");
            for flow in &self.fund_flows {
                let token = flow
                    .token
                    .map(|t| format_addr(&t))
                    .unwrap_or_else(|| "ETH".to_string());
                let value_str = format!("{}", flow.value);
                md.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    flow.step_index,
                    format_addr(&flow.from),
                    format_addr(&flow.to),
                    value_str,
                    token
                ));
            }
            md.push_str(
                "\n> **Note**: Only ERC-20 Transfer events and ETH value transfers are captured. ",
            );
            md.push_str(
                "Flash loan amounts detected via callback analysis are not reflected here.\n\n",
            );
        }

        // Storage Changes (with value interpretation)
        md.push_str("## Storage Changes\n\n");
        if self.storage_diffs.is_empty() {
            md.push_str("No storage modifications detected.\n\n");
        } else {
            md.push_str(&format!(
                "{} storage slot(s) modified during execution.\n\n",
                self.storage_diffs.len()
            ));
            md.push_str("| Contract | Slot | Old Value | New Value | Interpretation |\n");
            md.push_str("|---|---|---|---|---|\n");
            for diff in &self.storage_diffs {
                let interp = interpret_value(&diff.old_value, &diff.new_value);
                md.push_str(&format!(
                    "| {} | `{}` | `{}` | `{}` | {} |\n",
                    format_addr(&diff.address),
                    truncate_slot(&diff.slot),
                    diff.old_value,
                    diff.new_value,
                    interp
                ));
            }
            md.push_str(
                "\n> Slot decoding requires contract ABI — raw hashes shown (truncated).\n\n",
            );
        }

        // Key Steps
        md.push_str("## Key Steps\n\n");
        if self.key_steps.is_empty() {
            md.push_str("No key steps identified.\n\n");
        } else {
            md.push_str("Critical moments in the execution trace:\n\n");
            for step in &self.key_steps {
                let icon = match step.severity {
                    Severity::Critical => "[CRITICAL]",
                    Severity::Warning => "[WARNING]",
                    Severity::Info => "[INFO]",
                };
                md.push_str(&format!(
                    "- {icon} **Step {}**: {}\n",
                    step.step_index, step.annotation
                ));
            }
            md.push('\n');
        }

        // Affected Contracts (all contracts with roles and labels)
        md.push_str("## Affected Contracts\n\n");
        if self.affected_contracts.is_empty() {
            md.push_str("None identified.\n\n");
        } else {
            md.push_str(&format!(
                "{} contract(s) involved in this transaction.\n\n",
                self.affected_contracts.len()
            ));
            md.push_str("| Address | Role |\n");
            md.push_str("|---|---|\n");
            for addr in &self.affected_contracts {
                let role = self.contract_role(addr);
                md.push_str(&format!("| {} | {} |\n", format_addr(addr), role));
            }
            let has_unlabeled = self
                .affected_contracts
                .iter()
                .any(|a| known_label(a).is_none());
            if has_unlabeled {
                md.push_str(
                    "\n> Unlabeled contracts require manual identification via block explorer.\n\n",
                );
            } else {
                md.push('\n');
            }
        }

        // Suggested Fixes
        md.push_str("## Suggested Fixes\n\n");
        if self.suggested_fixes.is_empty() {
            md.push_str("No specific fixes suggested (no attack patterns detected).\n\n");
        } else {
            for fix in &self.suggested_fixes {
                md.push_str(&format!("- {fix}\n"));
            }
            md.push_str(
                "\n> **Note**: These are generic recommendations based on detected patterns. ",
            );
            md.push_str("Analyze the specific vulnerable contract for targeted fixes.\n\n");
        }

        // Conclusion
        md.push_str("## Conclusion\n\n");
        md.push_str(&self.generate_conclusion());
        md.push_str("\n\n---\n\n");
        md.push_str(
            "*This report was generated automatically by the Tokamak Smart Contract Autopsy Lab. \
             Manual analysis is recommended for comprehensive assessment.*\n",
        );

        md
    }

    /// Determine the role of a contract in this transaction.
    fn contract_role(&self, addr: &Address) -> String {
        // Check if it's a flash loan provider (heuristic)
        for pattern in &self.attack_patterns {
            if let AttackPattern::FlashLoan {
                provider: Some(p), ..
            } = pattern
                && p == addr
            {
                return "Suspected Flash Loan Provider".to_string();
            }
        }

        // Check if it has storage modifications
        if self.storage_diffs.iter().any(|d| d.address == *addr) {
            return "Storage Modified".to_string();
        }

        // Check if it's a fund flow participant
        if self
            .fund_flows
            .iter()
            .any(|f| f.from == *addr || f.to == *addr)
        {
            return "Fund Transfer".to_string();
        }

        "Interacted".to_string()
    }

    /// Generate a verdict-first summary.
    fn generate_summary(
        patterns: &[AttackPattern],
        flows: &[FundFlow],
        overview: &ExecutionOverview,
    ) -> String {
        let mut parts = Vec::new();

        // Verdict first
        if !patterns.is_empty() {
            let names: Vec<&str> = patterns.iter().map(pattern_name).collect();
            parts.push(format!("**VERDICT: {} detected.**", names.join(" + ")));
        } else {
            parts.push("**VERDICT: No known attack patterns detected.**".to_string());
        }

        // Execution context
        parts.push(format!(
            "Execution reached depth {} across {} contract(s) with {} external calls.",
            overview.max_call_depth, overview.unique_contracts, overview.call_count
        ));

        // Flash loan provider identification
        for pattern in patterns {
            if let AttackPattern::FlashLoan {
                provider: Some(p), ..
            } = pattern
            {
                let label = known_label(p)
                    .map(|l| format!(" ({l})"))
                    .unwrap_or_default();
                parts.push(format!(
                    "Suspected flash loan provider: `0x{p:x}`{label} (heuristic — first CALL at entry depth).",
                ));
            }
        }

        let eth_flows: Vec<_> = flows.iter().filter(|f| f.token.is_none()).collect();
        let token_flows: Vec<_> = flows.iter().filter(|f| f.token.is_some()).collect();

        if !eth_flows.is_empty() {
            let total_eth: U256 = eth_flows.iter().fold(U256::zero(), |acc, f| acc + f.value);
            parts.push(format!(
                "{} ETH transfer(s) totaling {} wei.",
                eth_flows.len(),
                total_eth
            ));
        }

        if !token_flows.is_empty() {
            parts.push(format!(
                "{} ERC-20 transfer(s) detected.",
                token_flows.len()
            ));
        }

        if overview.sstore_count > 0 {
            parts.push(format!("{} storage write(s).", overview.sstore_count));
        }

        parts.join(" ")
    }

    /// Generate a conclusion paragraph summarizing the attack.
    fn generate_conclusion(&self) -> String {
        let mut parts = Vec::new();

        if self.attack_patterns.is_empty() {
            parts.push(format!(
                "This transaction executed {} opcode steps across {} contract(s) \
                 with no recognized attack patterns.",
                self.total_steps, self.execution_overview.unique_contracts
            ));
            if !self.storage_diffs.is_empty() {
                parts.push(format!(
                    "{} storage slot(s) were modified.",
                    self.storage_diffs.len()
                ));
            }
            return parts.join(" ");
        }

        // Describe detected patterns
        for pattern in &self.attack_patterns {
            match pattern {
                AttackPattern::FlashLoan {
                    borrow_step,
                    repay_step,
                    provider,
                    ..
                } => {
                    let provider_str = provider
                        .map(|p| {
                            let label = known_label(&p)
                                .map(|l| format!(" ({l})"))
                                .unwrap_or_default();
                            format!("`0x{p:x}`{label}")
                        })
                        .unwrap_or_else(|| "an unidentified provider".to_string());

                    let callback_pct = if self.total_steps > 0 {
                        let span = repay_step.saturating_sub(*borrow_step);
                        (span as f64 / self.total_steps as f64 * 100.0) as u32
                    } else {
                        0
                    };

                    parts.push(format!(
                        "This transaction exhibits a **Flash Loan** attack pattern. \
                         The suspected provider is {provider_str} \
                         (identified heuristically as the first external CALL at entry depth). \
                         The exploit executed within a callback spanning steps {borrow_step}–{repay_step} \
                         ({callback_pct}% of total execution)."
                    ));
                }
                AttackPattern::Reentrancy {
                    target_contract,
                    reentrant_call_step,
                    state_modified_step,
                    ..
                } => {
                    parts.push(format!(
                        "A **Reentrancy** attack was detected targeting {}. \
                         Re-entry occurred at step {reentrant_call_step}, \
                         followed by state modification at step {state_modified_step}.",
                        format_addr(target_contract)
                    ));
                }
                AttackPattern::PriceManipulation { .. } => {
                    parts.push(
                        "A **Price Manipulation** pattern was detected: \
                         oracle reads before and after a swap suggest price influence."
                            .to_string(),
                    );
                }
                AttackPattern::AccessControlBypass { contract, .. } => {
                    parts.push(format!(
                        "An **Access Control Bypass** was detected on {}.",
                        format_addr(contract)
                    ));
                }
            }
        }

        // Storage impact analysis (unique insight, not timeline copy)
        if !self.storage_diffs.is_empty() {
            let storage_desc: Vec<String> = self
                .storage_diffs
                .iter()
                .map(|diff| {
                    let interp = interpret_value(&diff.old_value, &diff.new_value);
                    format!("{}: {}", format_addr(&diff.address), interp.to_lowercase())
                })
                .collect();
            parts.push(format!(
                "\n\n**Storage impact:** {}.",
                storage_desc.join("; ")
            ));
        }

        // Affected scope + defense recommendation
        if !self.affected_contracts.is_empty() {
            parts.push(format!(
                "\n\n{} contract(s) were involved, with {} storage modification(s). \
                 Manual analysis of the affected contracts is recommended to confirm \
                 the attack vector and assess full impact.",
                self.affected_contracts.len(),
                self.storage_diffs.len()
            ));
        }

        parts.join("")
    }

    fn compute_overview(steps: &[StepRecord]) -> ExecutionOverview {
        use std::collections::{HashMap, HashSet};

        let mut max_depth: usize = 0;
        let mut contracts = HashSet::new();
        let mut call_count = 0usize;
        let mut sstore_count = 0usize;
        let mut sload_count = 0usize;
        let mut log_count = 0usize;
        let mut create_count = 0usize;

        // Aggregate opcodes by display name to avoid PUSHn/DUPn/SWAPn duplicates
        let mut name_freq: HashMap<&str, usize> = HashMap::new();

        for step in steps {
            if step.depth > max_depth {
                max_depth = step.depth;
            }
            contracts.insert(step.code_address);
            *name_freq.entry(opcode_name(step.opcode)).or_default() += 1;

            match step.opcode {
                0xF1 | 0xF2 | 0xF4 | 0xFA => call_count += 1,
                0xF0 | 0xF5 => create_count += 1,
                0x54 => sload_count += 1,
                0x55 => sstore_count += 1,
                0xA0..=0xA4 => log_count += 1,
                _ => {}
            }
        }

        // Top 5 opcodes (aggregated by name — no PUSHn duplicates)
        let mut freq_vec: Vec<(&str, usize)> = name_freq.into_iter().collect();
        freq_vec.sort_by(|a, b| b.1.cmp(&a.1));
        let top_opcodes: Vec<(u8, String, usize)> = freq_vec
            .into_iter()
            .take(5)
            .map(|(name, count)| (0, name.to_string(), count))
            .collect();

        ExecutionOverview {
            max_call_depth: max_depth,
            unique_contracts: contracts.len(),
            call_count,
            sstore_count,
            sload_count,
            log_count,
            create_count,
            top_opcodes,
        }
    }

    fn identify_key_steps(
        patterns: &[AttackPattern],
        flows: &[FundFlow],
        steps: &[StepRecord],
    ) -> Vec<AnnotatedStep> {
        let mut key = Vec::new();
        let mut used_indices = std::collections::HashSet::new();

        for pattern in patterns {
            match pattern {
                AttackPattern::Reentrancy {
                    reentrant_call_step,
                    state_modified_step,
                    ..
                } => {
                    used_indices.insert(*reentrant_call_step);
                    key.push(AnnotatedStep {
                        step_index: *reentrant_call_step,
                        annotation: "Re-entrant call detected".to_string(),
                        severity: Severity::Critical,
                    });
                    used_indices.insert(*state_modified_step);
                    key.push(AnnotatedStep {
                        step_index: *state_modified_step,
                        annotation: "State modified after re-entry".to_string(),
                        severity: Severity::Critical,
                    });
                }
                AttackPattern::FlashLoan {
                    borrow_step,
                    repay_step,
                    borrow_amount,
                    provider,
                    ..
                } => {
                    let borrow_desc = if *borrow_amount > U256::zero() {
                        format!("Flash loan borrow: {borrow_amount} wei")
                    } else {
                        let prov = provider
                            .map(|p| {
                                known_label(&p)
                                    .map(|l| format!(" via {l}"))
                                    .unwrap_or_default()
                            })
                            .unwrap_or_default();
                        format!(
                            "Flash loan callback entry{prov} (amount unknown — detected via depth analysis)"
                        )
                    };
                    used_indices.insert(*borrow_step);
                    key.push(AnnotatedStep {
                        step_index: *borrow_step,
                        annotation: borrow_desc,
                        severity: Severity::Warning,
                    });
                    used_indices.insert(*repay_step);
                    key.push(AnnotatedStep {
                        step_index: *repay_step,
                        annotation: "Flash loan callback exit / repayment".to_string(),
                        severity: Severity::Warning,
                    });
                }
                AttackPattern::PriceManipulation {
                    oracle_read_before,
                    swap_step,
                    oracle_read_after,
                    ..
                } => {
                    used_indices.insert(*oracle_read_before);
                    key.push(AnnotatedStep {
                        step_index: *oracle_read_before,
                        annotation: "Oracle price read (before manipulation)".to_string(),
                        severity: Severity::Warning,
                    });
                    used_indices.insert(*swap_step);
                    key.push(AnnotatedStep {
                        step_index: *swap_step,
                        annotation: "Swap / price manipulation".to_string(),
                        severity: Severity::Critical,
                    });
                    used_indices.insert(*oracle_read_after);
                    key.push(AnnotatedStep {
                        step_index: *oracle_read_after,
                        annotation: "Oracle price read (after manipulation)".to_string(),
                        severity: Severity::Warning,
                    });
                }
                AttackPattern::AccessControlBypass { sstore_step, .. } => {
                    used_indices.insert(*sstore_step);
                    key.push(AnnotatedStep {
                        step_index: *sstore_step,
                        annotation: "SSTORE without access control check".to_string(),
                        severity: Severity::Warning,
                    });
                }
            }
        }

        // Annotate ETH transfers
        for flow in flows {
            if flow.token.is_none() && flow.value > U256::zero() {
                used_indices.insert(flow.step_index);
                key.push(AnnotatedStep {
                    step_index: flow.step_index,
                    annotation: format!("ETH transfer: {} wei", flow.value),
                    severity: Severity::Info,
                });
            }
        }

        // Annotate ERC-20 transfers
        for flow in flows {
            if flow.token.is_some() && !used_indices.contains(&flow.step_index) {
                let token_str = flow.token.map(|t| format_addr(&t)).unwrap_or_default();
                used_indices.insert(flow.step_index);
                key.push(AnnotatedStep {
                    step_index: flow.step_index,
                    annotation: format!(
                        "ERC-20 transfer ({}): {} → {}",
                        token_str,
                        format_addr(&flow.from),
                        format_addr(&flow.to)
                    ),
                    severity: Severity::Info,
                });
            }
        }

        // Annotate SSTORE events (state changes)
        for step in steps {
            if step.opcode == 0x55 && !used_indices.contains(&step.step_index) {
                let desc = if let Some(writes) = &step.storage_writes {
                    if let Some(w) = writes.first() {
                        let interp = interpret_value(&w.old_value, &w.new_value);
                        format!("SSTORE on {}: {}", format_addr(&step.code_address), interp)
                    } else {
                        format!("SSTORE on {}", format_addr(&step.code_address))
                    }
                } else {
                    format!("SSTORE on {}", format_addr(&step.code_address))
                };
                used_indices.insert(step.step_index);
                key.push(AnnotatedStep {
                    step_index: step.step_index,
                    annotation: desc,
                    severity: Severity::Info,
                });
            }
        }

        // Annotate CREATE/CREATE2 events
        for step in steps {
            if (step.opcode == 0xF0 || step.opcode == 0xF5)
                && !used_indices.contains(&step.step_index)
            {
                let op_name = if step.opcode == 0xF0 {
                    "CREATE"
                } else {
                    "CREATE2"
                };
                used_indices.insert(step.step_index);
                key.push(AnnotatedStep {
                    step_index: step.step_index,
                    annotation: format!("{op_name} by {}", format_addr(&step.code_address)),
                    severity: Severity::Info,
                });
            }
        }

        key.sort_by_key(|s| s.step_index);
        key
    }

    /// Collect ALL contracts involved in the transaction, not just fund flow/storage participants.
    fn collect_affected_contracts(
        steps: &[StepRecord],
        patterns: &[AttackPattern],
        flows: &[FundFlow],
        diffs: &[StorageWrite],
    ) -> Vec<Address> {
        let mut addrs: Vec<Address> = Vec::new();
        let mut push_unique = |addr: Address| {
            if !addrs.contains(&addr) {
                addrs.push(addr);
            }
        };

        // All contracts from execution trace (preserves first-seen order)
        for step in steps {
            push_unique(step.code_address);
        }

        // Flash loan providers
        for pattern in patterns {
            if let AttackPattern::FlashLoan {
                provider: Some(p), ..
            } = pattern
            {
                push_unique(*p);
            }
        }

        // Fund flow participants
        for flow in flows {
            push_unique(flow.from);
            push_unique(flow.to);
        }

        // Storage diff targets
        for diff in diffs {
            push_unique(diff.address);
        }

        addrs
    }

    fn suggest_fixes(patterns: &[AttackPattern]) -> Vec<String> {
        let mut fixes = Vec::new();
        for pattern in patterns {
            match pattern {
                AttackPattern::Reentrancy { .. } => {
                    fixes.push("Add a reentrancy guard (e.g., OpenZeppelin ReentrancyGuard) to state-changing functions.".to_string());
                    fixes.push("Follow the checks-effects-interactions pattern: update state before external calls.".to_string());
                }
                AttackPattern::FlashLoan { .. } => {
                    fixes.push("Validate account solvency after all balance-modifying operations (e.g., donateToReserves, mint, burn).".to_string());
                    fixes.push("Add flash loan protection: ensure functions that destroy collateral check the caller's liquidity position.".to_string());
                }
                AttackPattern::PriceManipulation { .. } => {
                    fixes.push("Use a decentralized oracle (e.g., Chainlink) with TWAP instead of spot AMM prices.".to_string());
                    fixes.push("Add price deviation checks: revert if price moves > X% in a single transaction.".to_string());
                }
                AttackPattern::AccessControlBypass { .. } => {
                    fixes.push("Add access control modifiers (onlyOwner, role-based) to state-changing functions.".to_string());
                    fixes.push("Use OpenZeppelin AccessControl for role management.".to_string());
                }
            }
        }
        fixes.dedup();
        fixes
    }
}
