# AI Agent Integration — Design Overview

> Feature flag: `ai_agent` | Status: Phase 1 MVP complete (2026-03-05)
> Full PoC report: [ai-agent-poc-report.md](ai-agent-poc-report.md)

## Why

Argus's rule-based detection pipeline has four classifiers (reentrancy, flash loan, price manipulation, access control) and a statistical anomaly detector with placeholder calibration data. This means:

- **Only known patterns are detected** — novel attacks slip through
- **High false-positive rate** — heuristic scores can't distinguish malicious from legitimate DeFi activity
- **No reasoning** — alerts return scores without human-readable explanations

An LLM layer addresses all three: it reasons over structured EVM traces to catch unknown patterns, reduces false positives through contextual judgment, and provides natural-language evidence for every verdict.

## Architecture

```
Pre-Filter (rule-based, ~10-50us/tx)
    |
    +-- Immediate: rule-based alert emitted (existing pipeline)
    |
    v  suspicious TX (async)
Context Extractor
    |  opcode trace -> AgentContext JSON (~2-5KB)
    v
CostTracker budget check
    |
    +-- budget exhausted -> SKIP (keep rule-based result)
    |
    v
Screening Model (fast, cheap)
    |
    +-- confidence < 0.6 -> keep rule-based result only
    |
    v  confidence >= 0.6 (escalate)
Deep Analysis Model (accurate, slower)
    |
    v
AgentVerdict + Hallucination Guard (evidence verification)
    |
    +-- is_attack: true  -> enrich alert with AI reasoning
    +-- is_attack: false -> cancel alert + log false_positive_reason
```

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Integration model | Additive layer, not replacement | Rule-based pipeline preserved; AI enhances, never blocks |
| 2-tier model | Screening (cheap) + Deep (accurate) | 80% of TXs filtered by cheap model; only ~20% escalate |
| Provider abstraction | `AiClient` trait | Swap between LiteLLM proxy and direct API calls |
| Cost control | CostTracker with daily/monthly budgets | Auto-disable at budget threshold; circuit breaker on API failures |
| Hallucination guard | Programmatic evidence verification | Every AI claim cross-checked against actual AgentContext data |
| Async 2-pass alerts | Rule-based immediate, AI enriches later | No latency impact on real-time pipeline |

## Data Model

### AgentContext (input to AI)

Extracted from EVM opcode traces by `ContextExtractor`:

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | H256 | Transaction hash |
| `block_number` | u64 | Block number |
| `from` / `to` | Address | Sender / Receiver |
| `value_wei` | U256 | ETH transferred |
| `gas_used` | u64 | Gas consumed |
| `succeeded` | bool | TX success status |
| `revert_count` | u32 | Internal revert count (reentrancy indicator) |
| `suspicious_score` | f64 | Pre-filter score |
| `call_graph` | Vec\<CallFrame\> | Call tree with depth, value, selector, revert status |
| `storage_mutations` | Vec\<StorageMutation\> | SSTORE operations with `in_callback` flag |
| `erc20_transfers` | Vec\<TokenTransfer\> | ERC-20 Transfer events |
| `eth_transfers` | Vec\<EthTransfer\> | ETH value transfers |
| `log_events` | Vec\<LogEvent\> | Non-Transfer events (Swap, Sync, Approval, etc.) |
| `delegatecalls` | Vec\<DelegateCallInfo\> | DELEGATECALL targets |
| `contract_creations` | Vec\<ContractCreation\> | CREATE/CREATE2 deployments |

### AgentVerdict (output from AI)

| Field | Type | Description |
|-------|------|-------------|
| `is_attack` | bool | Attack determination |
| `confidence` | f64 | Confidence score (0.0 - 1.0) |
| `attack_type` | Option\<AttackType\> | Reentrancy, FlashLoan, PriceManipulation, AccessControl, FrontRunning, Sandwich, Other |
| `reasoning` | String | Natural-language explanation |
| `evidence` | Vec\<String\> | Specific evidence items |
| `evidence_valid` | bool | Hallucination Guard verification result |
| `false_positive_reason` | Option\<String\> | Why this is not an attack (if applicable) |
| `model_used` | String | Which model produced this verdict |
| `tokens_used` | u32 | Token consumption |
| `latency_ms` | u64 | Response time |

## Hallucination Guard

Every evidence item returned by the AI is cross-checked against the actual `AgentContext`:

| Check | Source | Pass Criteria |
|-------|--------|---------------|
| Addresses mentioned | call_graph, transfers, delegatecalls | Address exists in at least one field |
| Amounts mentioned | erc20_transfers, eth_transfers | Within +/-10% of actual value |
| Function selectors | call_graph[].input_selector | 4-byte match |
| Events mentioned | log_events[].topic0 | Topic hash match |
| Evidence count | -- | At least 1 item (empty evidence rejected) |

If any check fails, `evidence_valid = false` — the verdict is flagged for human review.

## Cost Control

| Mechanism | Default | Purpose |
|-----------|---------|---------|
| Monthly budget | $150 | Hard cap — AI disabled when reached |
| Daily limit | $10 | Prevent single-day spikes |
| Hourly rate limit | 100 requests | Smooth out burst traffic |
| Per-block concurrency | 3 max | Prevent block-level cost explosion |
| Circuit breaker | 5 consecutive failures → 10min cooldown | Protect against API outages |

Budget is tracked in a JSON file with automatic daily/monthly reset.

## Module Structure

```
src/sentinel/ai/
├── mod.rs              # Module exports + feature gate
├── types/              # AgentContext, AgentVerdict, AttackType, CostTracker
├── context.rs          # ContextExtractor (StepRecord[] -> AgentContext)
├── judge.rs            # AiJudge (2-tier screening -> deep pipeline)
├── guard.rs            # Hallucination Guard (evidence verification)
├── client/             # AiClient trait + LiteLLMClient + AnthropicClient
├── cost.rs             # CostTracker persistence (JSON, daily/monthly reset)
├── ai_config.rs        # TOML config for [ai] section
├── rate_limit.rs       # HourlyRateTracker + BlockConcurrencyTracker
├── circuit_breaker.rs  # CircuitBreaker for API failure protection
├── prompts.rs          # System prompt (5 attack patterns)
└── fixtures.rs         # Fixture loader utilities
```

All AI code is gated behind `#[cfg(feature = "ai_agent")]` — the default build is unaffected.

## Configuration

```toml
[ai]
enabled = true
backend = "litellm"                          # "anthropic" | "litellm"
screening_model = "gemini-3-flash"
deep_model = "gemini-3-pro"
is_suspicious_confidence_threshold = 0.6     # escalation threshold
monthly_budget_usd = 150.0
daily_limit_usd = 10.0
hourly_rate_limit = 100
max_concurrent_per_block = 3
request_timeout_secs = 30
max_retries = 3
```

## PoC Results (Phase 0)

- **Accuracy**: 100% (13/13 fixtures — 3 attack + 10 benign)
- **Cost per request**: $0.009-0.016
- **Monthly projection**: $67-250 (cache-rate dependent)
- **Model**: Gemini 3 Flash (screening) + Gemini 3 Pro (deep) via LiteLLM proxy

## Phase Status

| Phase | Status | Deliverables |
|-------|--------|-------------|
| Phase 0: PoC | Complete | 13 fixtures, 100% accuracy, cost simulation |
| Phase 1: MVP | Complete | ContextExtractor, 2-tier AiJudge, HallucinationGuard, CostTracker, CircuitBreaker, Sentinel integration (~6,500 LoC, 145 tests) |
| Phase 2: Optimization | Planned | Prompt tuning, context compression, AI metrics dashboard |
| Phase 3: Advanced | Planned | Tool-use integration, sandwich/MEV detection, feedback loop |

## Known Limitations

- `input_selector` is `None` for all calls (recorder.rs calldata capture planned for Phase 2)
- `CREATE` deployed address is `Address::zero()` (ethrex LEVM limitation)
- Hallucination Guard amount tolerance (10%) is a placeholder — needs calibration with real data
