//! Autopsy report generation (JSON + Markdown).

use ethrex_common::{Address, H256, U256};
use serde::Serialize;

use crate::types::{StepRecord, StorageWrite};

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

fn pattern_name(pattern: &AttackPattern) -> &'static str {
    match pattern {
        AttackPattern::Reentrancy { .. } => "Reentrancy",
        AttackPattern::FlashLoan { .. } => "Flash Loan",
        AttackPattern::PriceManipulation { .. } => "Price Manipulation",
        AttackPattern::AccessControlBypass { .. } => "Access Control Bypass",
    }
}

fn format_pattern_detail(pattern: &AttackPattern) -> String {
    match pattern {
        AttackPattern::Reentrancy {
            target_contract,
            reentrant_call_step,
            state_modified_step,
            call_depth_at_entry,
        } => {
            format!(
                "- **Target**: {}\n\
                 - **Re-entrant call at step**: {reentrant_call_step}\n\
                 - **State modified at step**: {state_modified_step}\n\
                 - **Entry depth**: {call_depth_at_entry}\n",
                format_addr(target_contract)
            )
        }
        AttackPattern::FlashLoan {
            borrow_step,
            borrow_amount,
            repay_step,
            repay_amount,
            provider,
            token,
        } => {
            let mut detail = String::new();
            if let Some(p) = provider {
                detail.push_str(&format!(
                    "- **Suspected provider** (heuristic): {}\n",
                    format_addr(p)
                ));
            }
            if let Some(t) = token {
                detail.push_str(&format!("- **Token**: {}\n", format_addr(t)));
            }
            if *borrow_amount > U256::zero() {
                detail.push_str(&format!(
                    "- **Borrow at step**: {borrow_step} ({borrow_amount} wei)\n"
                ));
            } else {
                detail.push_str(&format!(
                    "- **Borrow at step**: {borrow_step} (detected via callback depth analysis)\n"
                ));
            }
            if *repay_amount > U256::zero() {
                detail.push_str(&format!(
                    "- **Repay at step**: {repay_step} ({repay_amount} wei)\n"
                ));
            } else {
                detail.push_str(&format!("- **Repay at step**: {repay_step}\n"));
            }
            detail
        }
        AttackPattern::PriceManipulation {
            oracle_read_before,
            swap_step,
            oracle_read_after,
            price_delta_percent,
        } => {
            let delta_str = if *price_delta_percent < 0.0 {
                "unknown (insufficient SLOAD data)".to_string()
            } else {
                format!("{price_delta_percent:.1}%")
            };
            format!(
                "- **Oracle read before**: step {oracle_read_before}\n\
                     - **Swap/manipulation**: step {swap_step}\n\
                     - **Oracle read after**: step {oracle_read_after}\n\
                     - **Price delta**: {delta_str}\n"
            )
        }
        AttackPattern::AccessControlBypass {
            sstore_step,
            contract,
        } => {
            format!(
                "- **SSTORE at step**: {sstore_step}\n\
                 - **Contract**: {}\n",
                format_addr(contract)
            )
        }
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Format an address with a known label if available.
fn format_addr(addr: &Address) -> String {
    if let Some(label) = known_label(addr) {
        format!("`0x{addr:x}` ({label})")
    } else {
        format!("`0x{addr:x}`")
    }
}

/// Truncate a storage slot hash for display: `0xabcdef01…89abcdef`.
fn truncate_slot(slot: &H256) -> String {
    let hex = format!("{:x}", slot);
    if hex.len() > 16 {
        format!("0x{}…{}", &hex[..8], &hex[hex.len() - 8..])
    } else {
        format!("0x{hex}")
    }
}

/// Look up well-known mainnet contract addresses.
///
/// 80+ labels covering stablecoins, DEXes, lending, bridges, oracles,
/// infrastructure, flash loan providers, and MEV contracts.
pub fn known_label(addr: &Address) -> Option<&'static str> {
    let hex = format!("{addr:x}");
    match hex.as_str() {
        // === Stablecoins & tokens ===
        "6b175474e89094c44da98b954eedeac495271d0f" => Some("DAI"),
        "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" => Some("USDC"),
        "dac17f958d2ee523a2206206994597c13d831ec7" => Some("USDT"),
        "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => Some("WETH"),
        "2260fac5e5542a773aa44fbcfedf7c193bc2c599" => Some("WBTC"),
        "853d955acef822db058eb8505911ed77f175b99e" => Some("FRAX"),
        "5f98805a4e8be255a32880fdec7f6728c6568ba0" => Some("LUSD"),
        "57ab1ec28d129707052df4df418d58a2d46d5f51" => Some("sUSD"),
        "03ab458634910aad20ef5f1c8ee96f1d6ac54919" => Some("RAI"),
        "056fd409e1d7a124bd7017459dfea2f387b6d5cd" => Some("GUSD"),
        "4fabb145d64652a948d72533023f6e7a623c7c53" => Some("BUSD"),
        "0000000000085d4780b73119b644ae5ecd22b376" => Some("TUSD"),
        "8e870d67f660d95d5be530380d0ec0bd388289e1" => Some("USDP"),
        "1f9840a85d5af5bf1d1762f925bdaddc4201f984" => Some("UNI"),
        "7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9" => Some("AAVE"),
        "514910771af9ca656af840dff83e8264ecf986ca" => Some("LINK"),
        "9f8f72aa9304c8b593d555f12ef6589cc3a579a2" => Some("MKR"),
        "c011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f" => Some("SNX"),
        "d533a949740bb3306d119cc777fa900ba034cd52" => Some("CRV"),
        "ba100000625a3754423978a60c9317c58a424e3d" => Some("BAL"),
        // === Lido ===
        "ae7ab96520de3a18e5e111b5eaab095312d7fe84" => Some("Lido stETH"),
        "7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0" => Some("wstETH"),
        // === Aave V2 ===
        "7d2768de32b0b80b7a3454c06bdac94a69ddc7a9" => Some("Aave V2 Pool"),
        "028171bca77440897b824ca71d1c56cac55b68a3" => Some("Aave aDAI"),
        "030ba81f1c18d280636f32af80b9aad02cf0854e" => Some("Aave aWETH"),
        "1982b2f5814301d4e9a8b0201555376e62f82428" => Some("Aave astETH"),
        // === Aave V3 ===
        "87870bca3f3fd6335c3f4ce8392d69350b4fa4e2" => Some("Aave V3 Pool"),
        "2f39d218133afab8f2b819b1066c7e434ad94e9e" => Some("Aave V3 PoolAddressesProvider"),
        // === Morpho ===
        "bbbbbbbbbb9cc5e90e3b3af64bdaf62c37eeffcb" => Some("Morpho Blue"),
        // === Spark ===
        "c13e21b648a5ee794902342038ff3adab66be987" => Some("Spark Lending Pool"),
        // === Compound ===
        "4ddc2d193948926d02f9b1fe9e1daa0718270ed5" => Some("Compound cETH"),
        "5d3a536e4d6dbd6114cc1ead35777bab948e3643" => Some("Compound cDAI"),
        "39aa39c021dfbae8fac545936693ac917d5e7563" => Some("Compound cUSDC"),
        "3d9819210a31b4961b30ef54be2aed79b9c9cd3b" => Some("Compound Comptroller"),
        "c3d688b66703497daa19211eedff47f25384cdc3" => Some("Compound V3 cUSDC"),
        // === Uniswap ===
        "7a250d5630b4cf539739df2c5dacb4c659f2488d" => Some("Uniswap V2 Router"),
        "5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f" => Some("Uniswap V2 Factory"),
        "e592427a0aece92de3edee1f18e0157c05861564" => Some("Uniswap V3 Router"),
        "68b3465833fb72a70ecdf485e0e4c7bd8665fc45" => Some("Uniswap V3 Router 02"),
        "1f98431c8ad98523631ae4a59f267346ea31f984" => Some("Uniswap V3 Factory"),
        "c36442b4a4522e871399cd717abdd847ab11fe88" => Some("Uniswap V3 Positions NFT"),
        "000000000022d473030f116ddee9f6b43ac78ba3" => Some("Uniswap Permit2"),
        "3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad" => Some("Uniswap Universal Router"),
        // === SushiSwap ===
        "d9e1ce17f2641f24ae83637ab66a2cca9c378b9f" => Some("SushiSwap Router"),
        // === Curve ===
        "bebc44782c7db0a1a60cb6fe97d0b483032ff1c7" => Some("Curve 3pool"),
        "b9fc157394af804a3578134a6585c0dc9cc990d4" => Some("Curve Factory"),
        "99a58482bd75cbab83b27ec03ca68ff489b5788f" => Some("Curve CryptoSwap Router"),
        // === Balancer ===
        "ba12222222228d8ba445958a75a0704d566bf2c8" => Some("Balancer V2 Vault"),
        // === 1inch ===
        "1111111254eeb25477b68fb85ed929f73a960582" => Some("1inch V5 Router"),
        // === Bridges ===
        "99c9fc46f92e8a1c0dec1b1747d010903e884be1" => Some("Optimism L1 Bridge"),
        "8315177ab297ba92a06054ce80a67ed4dbd7ed3a" => Some("Arbitrum Gateway"),
        "a0c68c638235ee32657e8f720a23cec1bfc6c3d8" => Some("Polygon PoS Bridge"),
        "3ee18b2214aff97000d974cf647e7c347e8fa585" => Some("Wormhole Token Bridge"),
        "40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf" => Some("Polygon ERC20 Bridge"),
        // === Oracles ===
        "5f4ec3df9cbd43714fe2740f5e3616155c5b8419" => Some("Chainlink ETH/USD"),
        "f4030086522a5beea4988f8ca5b36dbc97bee88c" => Some("Chainlink BTC/USD"),
        "2c1d072e956affc0d435cb7ac38ef18d24d9127c" => Some("Chainlink LINK/USD"),
        "8fffffd4afb6115b954bd326cbe7b4ba576818f6" => Some("Chainlink USDC/USD"),
        "47fb2585d2c56fe188d0e6ec628a38b74fceeedf" => Some("Uniswap V3 TWAP Oracle"),
        // === Infrastructure ===
        "ca11bde05977b3631167028862be2a173976ca11" => Some("Multicall3"),
        "4e59b44847b379578588920ca78fbf26c0b4956c" => Some("CREATE2 Deployer"),
        "d9db270c1b5e3bd161e8c8503c55ceabee709552" => Some("Gnosis Safe Singleton"),
        "a2327a938febf5fec13bacfb16ae10ecbc4cc280" => Some("Gnosis Safe ProxyFactory"),
        "c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d3c0d30001" => Some("EIP-7702 Delegation"),
        // === Flash Loan Providers ===
        "1e0447b19bb6ecfdae1e4ae1694b0c3659614e4e" => Some("dYdX SoloMargin"),
        "27182842e098f60e3d576794a5bffb0777e025d3" => Some("Euler Protocol"),
        "60744434d6339a6b27d73d9eda62b6f66a0a04fa" => Some("Euler SimpleLens"),
        "398ec7346dcd622edc5ae82352f02be94c62d119" => Some("Aave V1 Pool"),
        // === MakerDAO ===
        "9759a6ac90977b93b58547b4a71c78317f391a28" => Some("MakerDAO DSProxy Factory"),
        "5ef30b9986345249bc32d8928b7ee64de9435e39" => Some("MakerDAO Vat"),
        "35d1b3f3d7966a1dfe207aa4514c12a259a0492b" => Some("MakerDAO CDP Manager"),
        // === MEV ===
        "c0ffee254729296a45a3885639ac7e10f9d54979" => Some("MEV Block Builder"),
        "a69babef1ca67a37ffaf7a485dfff3382056e78c" => Some("Flashbots Protect"),
        // === Gnosis Protocol / CoW Swap ===
        "9008d19f58aabd9ed0d60971565aa8510560ab41" => Some("CoW Protocol Settlement"),
        // === ENS ===
        "00000000000c2e074ec69a0dfb2997ba6c7d2e1e" => Some("ENS Registry"),
        "57f1887a8bf19b14fc0df6fd9b2acc9af147ea85" => Some("ENS BaseRegistrar"),
        // === Other Notable Contracts ===
        "c36442b4a4522e871399cd717abdd847ab11fe88..ignored" => None,
        // === Cream Finance (hack-related) ===
        "44fbeb8ea7384d0b58f47e3a92d6dab2a6d8e6a1" => Some("Cream Finance"),
        // === Parity (hack-related) ===
        "863df6bfa4469f3ead0be8f9f2aae51c91a907b4" => Some("Parity Multisig Library"),
        // === Ronin (hack-related) ===
        "1a2a1c938ce3ec39b6d47113c7955baa9dd454f2" => Some("Ronin Gateway"),
        _ => None,
    }
}

/// Interpret a storage value change for human readability.
fn interpret_value(old: &U256, new: &U256) -> &'static str {
    if *new == U256::MAX {
        "MAX_UINT256 (infinite approval)"
    } else if old.is_zero() && !new.is_zero() {
        "New allocation (0 → nonzero)"
    } else if !old.is_zero() && new.is_zero() {
        "Cleared (nonzero → 0)"
    } else if *new > *old {
        "Increased"
    } else if *new < *old {
        "Decreased"
    } else {
        "Unchanged"
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x10 => "LT",
        0x11 => "GT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1A => "BYTE",
        0x1B => "SHL",
        0x1C => "SHR",
        0x1D => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x38 => "CODESIZE",
        0x39 => "CODECOPY",
        0x3A => "GASPRICE",
        0x3B => "EXTCODESIZE",
        0x3C => "EXTCODECOPY",
        0x3D => "RETURNDATASIZE",
        0x3E => "RETURNDATACOPY",
        0x3F => "EXTCODEHASH",
        0x40 => "BLOCKHASH",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x44 => "PREVRANDAO",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5A => "GAS",
        0x5B => "JUMPDEST",
        0x5F => "PUSH0",
        0x60..=0x7F => "PUSHn",
        0x80..=0x8F => "DUPn",
        0x90..=0x9F => "SWAPn",
        0xA0 => "LOG0",
        0xA1 => "LOG1",
        0xA2 => "LOG2",
        0xA3 => "LOG3",
        0xA4 => "LOG4",
        0xF0 => "CREATE",
        0xF1 => "CALL",
        0xF2 => "CALLCODE",
        0xF3 => "RETURN",
        0xF4 => "DELEGATECALL",
        0xF5 => "CREATE2",
        0xFA => "STATICCALL",
        0xFD => "REVERT",
        0xFE => "INVALID",
        0xFF => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}
