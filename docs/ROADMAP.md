# Argus Roadmap

**[Architecture Diagram](argus-architecture.html)** — Interactive architecture map with per-module file mapping

## Honest Assessment

Argus has strong code quality, but faces structural problems in external competitiveness.

| Problem | Severity | Summary |
|---------|----------|---------|
| ethrex dependency | **Critical** | ethrex client market share ~0%. The "L1 node integration" advantage has nowhere to materialize |
| Limited production detection record | **High** | 82 alerts raised (MEV/arb patterns) but zero confirmed exploit interceptions yet |
| Single-developer project | **High** | Bus Factor = 1. GitHub Discussions enabled, 5 good-first-issues created (#1–#5), but zero external contributors yet |
| High barrier to entry | **Medium** | Docker image available; `cargo build` requires Rust 1.85+ (~5 min first build) |
| All-in-one risk | **Medium** | All three modules are weaker than specialized competitors. Need to focus on Sentinel |

---

## Phase 0: Foundation (Immediate — 2 weeks)

Goal: **Create a path to "see real results within 5 minutes."**

| # | Item | Status |
|---|------|--------|
| 0-1 | Publish Docker Hub image (`docker run tokamak/argus-demo`) | Done (v0.1.0) |
| 0-2 | Write CONTRIBUTING.md | Done |
| 0-3 | Enable GitHub Discussions | Done |
| 0-4 | Add 3–5 real mainnet hack TXs as test fixtures | Done (Balancer, Bybit, Poly Network) |
| 0-5 | Create 5 issues with `good first issue` label for external contributors | Done (#1–#5) |
| 0-6 | Smoke test: replay 1–2 historical hack TXs — pipeline sanity check level | Done (8 offline smoke tests) |

---

## Phase 1: Breaking Free from ethrex — RPC Independence + Reth ExEx (Q2 2026)

Goal: **Make Argus usable without ethrex and prepare to enter the Reth ecosystem.**

Argus currently runs only on top of ethrex LEVM. With ethrex's market share at ~0%, this is a critical constraint.

### Solution — Two Sequential Tracks (Parallelize if Contributors Join)

```
Current:  Argus → ethrex LEVM (embedded) → Block analysis

Track A:  Argus → RPC endpoint (external) → Block analysis  ← Promote to first-class citizen
Track B:  Argus → Reth ExEx (plugin)     → Block analysis  ← Parallel PoC

Keep:     Argus → ethrex LEVM (embedded) → Block analysis  ← Retain as optimal performance path
```

| # | Item | Description | Priority | Status |
|---|------|-------------|----------|--------|
| 1-1 | **RPC-based Sentinel mode** | Connect to any Ethereum RPC endpoint, poll new blocks, run pre-filter + deep analysis on each TX. No ethrex required | **#1** — Prerequisite for expanding the user base | Done |
| 1-2 | **Autopsy CLI improvements** | One-line mainnet TX forensic analysis with `argus autopsy --tx 0x... --rpc https://eth.llamarpc.com`. RPC client already exists; only CLI improvements needed | High | Done |
| 1-3 | **Reth ExEx PoC** | PoC to determine if Sentinel can be integrated via Reth's Execution Extensions. Reth's market share is growing, making this the most promising path to realize the "node-embedded" vision | **#2** — Start after 1-1 is complete, or parallelize if external contributors join | Deferred to Q3 |

### Why Reth ExEx Was Promoted from "Long-term Consideration"

- Staying locked to ethrex means TAM (Total Addressable Market) converges to 0
- Reth is the fastest-growing Rust-based Ethereum client
- Security plugins via ExEx are the most realistic path to realize Argus's "node-embedded" vision
- At PoC level, the resource burden is manageable

### Completion Criteria

**Track A (RPC mode)** — Core milestone of Phase 1:
- **All Ethereum node operators** can use Argus (from ethrex-only → entire ecosystem)
- Users of RPC providers like Alchemy/Infura also become target users
- Start with a single line: `docker run tokamak/argus-demo --rpc https://...`

**Track B (Reth ExEx PoC)** — After Track A completion, or when contributors join:
- Minimal demo showing Sentinel pre-filter running via Reth ExEx
- Prove in one sentence: "You can enable the Argus security layer on a Reth node"

---

## Phase 2: Building Production Track Record (Q2–Q3 2026)

Goal: **Turn "would have detected" into "did detect."**

| # | Item | Description | Status |
|---|------|-------------|--------|
| 2-1 | **14-day continuous mainnet operation** | Run RPC-mode Sentinel on Ethereum mainnet via AWS ECS Fargate for 14 days. Record blocks scanned, suspicious TXs flagged, and detection results. See [deployment guide](deployment.md) | In progress (~Mar 19 target) |
| 2-2 | **Document detection results** | "In Q2 2026, scanned X blocks on mainnet, flagged Y suspicious TXs, confirmed Z detections" — the first production track record report | Done — [detection report](detection-report.md) (82 alerts / 11.1h) |
| 2-3 | **Systematic replay verification of historical hacks** | Run 5+ major hack TXs (Balancer, Bybit, Euler, etc.) through Autopsy, produce a report with quantitative results (detection rate, confidence, latency). Unlike Phase 0-6 smoke tests, this is a systematic benchmark | Done — [replay benchmark](../src/tests/replay_benchmark.rs) |
| 2-4 | **Latency benchmark** | Measure and publish Pre-filter μs/tx and Deep Analyzer ms/tx | Done — [latency bench](../examples/sentinel_latency_bench.rs) |

### Success Criteria

- "Argus raised 82 alerts scanning ~273K transactions (~3,300 blocks) on Ethereum mainnet" — initial baseline established (11.1h of 336h target); 14-day continuous operation in progress (~Mar 19 completion)

---

## Phase AI-0: LLM Integration PoC Validation — PASS (Completed 2026-03-05)

Goal: **Validate whether an LLM can analyze EVM opcode traces to detect attacks.**

Detailed design: [`PRD/`](../PRD/README.md) (5 documents). PoC results: [`docs/ai-agent-poc-report.md`](ai-agent-poc-report.md)

| # | Item | Description | Status |
|---|------|-------------|--------|
| AI-0-1 | **StepRecord→AgentContext mapping analysis** | Verify that ethrex LEVM StepRecord provides call_graph, storage_mutations, etc. | Completed |
| AI-0-2 | **Fixture conversion** | 3 attack TXs + 10 benign TXs → AgentContext JSON (13 total) | Completed |
| AI-0-3 | **LiteLLM (Gemini) accuracy measurement** | Achieved **100%** classification accuracy on 13 fixtures with gemini-3-flash/pro (target was 80%) | Completed |
| AI-0-4 | **SDK compatibility verification** | anthropic-sdk-rust found unsuitable → Adopted LiteLLM proxy (OpenAI-compatible) | Completed |
| AI-0-5 | **Cost simulation** | $0.009–0.016/req, $67–250/month (cache-rate dependent). Operable within $150 budget | Completed |

**Prerequisite:** `rpc_service.rs` detected_patterns bug — Fixed

**Result:** 100% accuracy (13/13) — Phase AI-1 MVP approved

Phase AI-1 completed (2026-03-05) → AI-2 (optimization, 2–3 weeks) → AI-3 (advanced features, 3–4 weeks)

---

## Phase AI-1: MVP Implementation — Completed (2026-03-05)

Goal: **ContextExtractor + 2-tier AI Judge + Hallucination Guard + Cost Control + Sentinel Integration**

| # | Item | Description | Status |
|---|------|-------------|--------|
| AI-1-1 | **CostTracker + CircuitBreaker + Config** | JSON persistence, daily/monthly reset, circuit breaker, TOML configuration | Completed |
| AI-1-2 | **ContextExtractor** | StepRecord[] → AgentContext (call_graph, storage_mutations, logs, transfers) | Completed |
| AI-1-3 | **AiJudge 2-tier + HallucinationGuard** | screening (gemini-3-flash) → escalation → deep (gemini-3-pro) + evidence verification | Completed |
| AI-1-4 | **Sentinel Pipeline integration** | Async AI judge integration in rpc_service.rs, SentinelAlert.agent_verdict field | Completed |

**Deliverables:** 18 new files, ~6,500 LoC, 145 new tests (total 767 pass + 27 ignored)

**Known limitations:** input_selector = None (Phase 2 will add calldata capture in recorder.rs), CREATE deployed = Address::zero()

---

## Phase 3: Adoption Growth (Q3–Q4 2026)

Goal: **Acquire the first external user.**

| # | Item | Description |
|---|------|-------------|
| 3-1 | **EVM trait abstraction + crates.io publish** | Extract `EvmExecutor` trait to decouple from ethrex. Publish `argus-core` (trait-only, no git deps) to crates.io. Keep `argus-ethrex` as a separate crate with git dependency. This unblocks `cargo install argus-core` while maintaining ethrex integration. Aligns with Reth ExEx direction (revm becomes a second `EvmExecutor` impl). Prerequisite: ethrex publishes to crates.io, OR trait abstraction is complete |
| 3-2 | **Reth ExEx integration** (depending on Phase 1-3 PoC results) | Reth users can activate Sentinel as a plugin. Shares `EvmExecutor` trait with 3-1 |
| 3-3 | **Focus on Sentinel** | Concentrate resources on Sentinel, the most differentiated of the three modules. Position as "an open-source runtime security tool specialized for Ethereum L1" rather than "all-in-one" |
| 3-4 | **Community growth** | Launch Discord/Telegram, publish regular security analysis content |

---

## Strategic Pivot Summary

| Previous Direction | New Direction |
|--------------------|---------------|
| Optimize for GitHub stars (marketing) | Optimize for production track record (product) |
| ethrex-only | RPC-independent mode as first-class citizen + parallel Reth ExEx |
| All-in-one (3 modules simultaneously) | Focus on Sentinel; others become auxiliary |
| Synthetic demos | Real mainnet/testnet data |
| Case studies (subjunctive) | Detection track record reports (factual) |
| "Need to build Rust to try it" | "One-line docker run" |
| "Block propagation at L1 node" (unverified) | "Open-source self-hosted runtime security" (verifiable) |
| Reth ExEx as long-term consideration | Reth ExEx PoC in Phase 1, sequential (parallel if contributors join) |
| Small team = medium risk | Single developer = high risk. Begin addressing immediately |
