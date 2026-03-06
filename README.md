# Argus

[![CI](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml/badge.svg)](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

**The Hundred-Eyed Guardian for Ethereum**

Real-time attack detection, post-hack forensics, and time-travel debugging for EVM transactions.

**Built for:** Protocol security teams, security researchers, and node operators seeking self-hosted Ethereum monitoring.

<p align="center">
  <img src="docs/assets/demo.gif" alt="Argus Sentinel Demo" width="800">
</p>

> Existing security tools (Slither, Mythril, Echidna) analyze contracts **before** deployment.
> Argus protects **after** deployment — detecting attacks as they happen and analyzing them when they've already occurred.

### See It in Action

```
$ cargo run --example sentinel_realtime_demo

 ┌─────────────────────────────────────────────────────┐
 │  Argus Sentinel — Real-Time Attack Detection Demo   │
 └─────────────────────────────────────────────────────┘

 Demo 1  Multi-TX Block Scanning
   TX 0: Simple ETH transfer (21k gas, success)  →  CLEAN
   TX 1: Flash loan via Aave (2.5M gas)          →  CLEAN
   TX 2: 5 ETH transfer, reverted (950k gas)     →  FLAGGED

   ⚠ Alert #2
     Priority: High   Score: 0.75
     Reason:   HighValueWithRevert, UnusualGas, SelfDestruct

 Demo 3  Mempool Pre-Filter (Pending TX Scanning)
   Mempool TXs scanned:  4
   Mempool TXs flagged:  3

 Demo 4  Auto-Pause Circuit Breaker
   Score below threshold — no pause triggered
   (Pre-filter-only alerts may not reach confidence threshold)
```

> No RPC key needed — demos run against local LEVM. Try it (~5 min first build, instant after):
> `git clone https://github.com/tokamak-network/Argus.git && cd Argus && cargo run --example sentinel_realtime_demo`
>
> **Quick path guide:** Security researcher? → Run the demo. DevOps? → Use [Docker](#docker). Developer? → [Build from source](#building).

---

## What Argus Does

> Core features (pre-filter, deep analyzer, alerts, forensics, debugger) are implemented and tested (815 tests). Some features (mempool monitoring, auto-pause, ML pipeline) are available in embedded mode only — not yet wired in the RPC-mode CLI. See [sentinel.toml.example](sentinel.toml.example) for details. Argus is currently running on **Ethereum mainnet** via AWS ECS Fargate — see [Deployment Guide](docs/deployment.md) and [Roadmap](docs/ROADMAP.md).

### Sentinel — Real-Time Attack Detection

A 2-stage detection pipeline integrated at the block processing level:

- **Pre-filter**: Receipt-based heuristics (~10-50μs/tx — see [latency bench](examples/sentinel_latency_bench.rs)) eliminate 99% of benign transactions
- **Deep analyzer**: Full opcode-level replay on suspicious transactions only
- **Mempool monitoring**: Detect attacks *before* they're included in a block *(embedded mode only; not yet in RPC-mode CLI)*
- **Auto-pause circuit breaker**: Optionally halt processing on critical alerts *(embedded mode only; disabled by default due to [slashing risk](docs/competitive-analysis.md#auto-pause-risk))*
- **Multi-channel alerts**: JSONL, Webhook (Slack/Discord/PagerDuty), WebSocket, Prometheus

### Autopsy Lab — Post-Hack Forensics

Replay any mainnet transaction and generate a forensic report:

- **Attack pattern classification**: Reentrancy, flash loans, price oracle manipulation, access control bypasses
- **Fund flow tracing**: Track ETH and ERC-20 token movements through the attack
- **Markdown report generation**: Structured timeline with attack phases, evidence, and suggested fixes

### Time-Travel Debugger

GDB-style interactive replay at opcode granularity:

- Forward/backward stepping through execution
- Breakpoints on program counter (PC)
- Full state inspection at any point in execution
- Fast step navigation

---

## Quick Start

### Run the Sentinel demo

```bash
git clone https://github.com/tokamak-network/Argus.git
cd Argus
cargo run --example sentinel_realtime_demo
```

This simulates a block containing both benign and malicious transactions, showing Sentinel's detection pipeline in action:

```
Demo 1  Multi-TX Block Scanning
  TX 0: Simple ETH transfer (21k gas, success)
  TX 1: Flash loan via Aave (2.5M gas, 6 ERC-20 transfers)
  TX 2: 5 ETH transfer, reverted (950k gas)

  Alert #2:
    Priority: High
    Score:    0.75
    Summary:  Pre-filter alert: high-value-revert, unusual-gas, self-destruct
    Reason:   HighValueWithRevert { value_wei: 5000000000000000000 }

Demo 3  Mempool Pre-Filter (Pending TX Scanning)
  Mempool TXs scanned:  4
  Mempool TXs flagged:  3

Demo 4  Auto-Pause Circuit Breaker
  Critical alert → block processing HALTED
```

### Run the Autopsy demo

```bash
cargo run --example reentrancy_demo
```

Deploys a vulnerable contract, executes a reentrancy attack, and runs full forensic analysis:

```
Phase 1  Deploy & Execute
  Execution: SUCCESS (gas_used=82107)
  Opcode steps recorded: 80

Phase 2  Verify Attack
  Max call depth: 4  (need >= 3 for reentrancy)
  CALL opcodes:   4
  SSTORE opcodes: 4  (attacker counter writes)
  Result: CONFIRMED — reentrancy pattern detected

Phase 3  AttackClassifier
  Reentrancy (target=0x...0043)
    confidence: 90.0%
    evidence: Re-entrant call at step 47
    evidence: State modified at step 69
    evidence: Value transfer during re-entry

Phase 4  FundFlowTracer
  ETH drain confirmed (victim -> attacker)

Phase 6  Summary
  Pre-filter: no receipt-level alert (TX succeeded with normal gas)
  Reentrancy was detected by the opcode-level classifier (Phase 3).
```

---

## Live Detection Results

Argus is running on **Ethereum mainnet** via AWS ECS Fargate (since March 2026). Results from the first 11.1 hours of continuous operation:

- **82 alerts raised**: 61 scored Critical by pre-filter (flash loan MEV patterns) + 21 High (high-value reverts, SelfDestruct) — alert priority levels, not confirmed exploits
- **Pre-filter flag rate**: 0.030% (target: <1%)
- **Deep replay**: 100% success (82/82), avg 69,259 opcode steps/TX
- **Zero downtime**, $7/month on Fargate

> No confirmed exploit interceptions yet — all alerts were MEV/arbitrage or revert patterns. Two reports cover different periods and configurations:
> - [Detection report](docs/detection-report.md) — 11.1h snapshot, `suspicion_threshold=0.3`, 82 alerts (high-sensitivity tuning)
> - [Operations report](docs/mainnet-report-march-2026.md) — 14-day run, `suspicion_threshold=0.7`, 14 alerts (production tuning)

## Historical Validation

The following are **retroactive, hypothetical** analyses of past exploits. Argus was not running at the time of these attacks. These demonstrate what the detection pipeline *would likely* produce on similar patterns. Some signals shown are planned but not yet implemented — see each analysis for details.

**[Retroactive Analysis: $128M Balancer V2 Exploit](docs/analysis-balancer-v2-exploit.md)**

$128M drained via rounding error in Balancer V2's `batchSwap` (Nov 2025). Argus's pre-filter would likely flag the unusual gas + ERC-20 transfer count; deep analyzer classifies as price manipulation (82% confidence).

**[Retroactive Analysis: $1.4B Bybit Exploit](docs/analysis-bybit-1.4b-exploit.md)**

$1.4B drained from Bybit's cold wallet via supply chain attack on Safe{Wallet} (Feb 2025). Argus's pre-filter would likely flag unusual gas pattern from the multisig; deep analyzer identifies proxy implementation overwrite. Full detection of proxy upgrade anomalies requires planned signal additions.

---

## How It Compares

| | Argus | Forta | Phalcon | Tenderly | Hexagate |
|---|---|---|---|---|---|
| Runtime detection | Yes | Yes (bot network) | Yes | Partial (alerts) | Yes |
| Mempool pre-detection | Yes* | Partial** | Yes | Yes | Yes |
| Post-hack forensics | **Yes** | No | No | Partial | No |
| Open source | **Fully** | Partial | No | No | No |
| Self-hosted | **Yes** | No (SaaS) | No (SaaS) | No (SaaS) | No (SaaS) |
| Multi-chain | No | Yes (7+) | Yes | Yes (109) | Yes |
| Production track record | **82 alerts / ~273K TXs / 11h uptime (Mar 2026~)** | 270M+ TX scanned | 20+ hacks blocked | 1.4M+ simulations | Undisclosed |

> \* Argus mempool monitoring is available in embedded mode only; not yet wired in RPC-mode CLI.
>
> \*\* Forta Firewall provides pre-execution screening for rollups, not L1 mempool monitoring ([details](docs/competitive-analysis.md)).
>
> Argus is early-stage but running on Ethereum mainnet via AWS ECS Fargate. 82 alerts raised in 11.1 hours (~3,300 blocks, ~273K TXs scanned), zero downtime, $7/month — see [detection report](docs/detection-report.md). No confirmed exploit interceptions yet; all alerts were MEV/arbitrage patterns. Its primary differentiator is being **fully open-source and self-hostable**. See [competitive analysis](docs/competitive-analysis.md) for an honest, detailed comparison.

---

## Architecture

> Interactive module map with file-level detail: [docs/argus-architecture.html](docs/argus-architecture.html)

```
                    ┌─────────────────────────────────────┐
                    │          Ethereum Network            │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │           Mempool Monitor            │
                    │     (pre-execution calldata scan)    │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────▼────────────────────────┐
              │              Sentinel Pipeline               │
              │                                              │
              │  ┌──────────┐    ┌────────────────────────┐ │
              │  │Pre-filter │───▶│    Deep Analyzer        │ │
              │  │ ~10-50μs  │    │ (opcode-level replay)  │ │
              │  │  per tx   │    │                        │ │
              │  └──────────┘    └───────────┬────────────┘ │
              └──────────────────────────────┼──────────────┘
                                             │
                    ┌────────────────────────▼─────────┐
                    │         Alert Dispatcher          │
                    │  JSONL / Webhook / WS / Prometheus │
                    └────────────────────────┬─────────┘
                                             │
                    ┌────────────────────────▼─────────┐
                    │      Auto-Pause Circuit Breaker   │
                    │   (halt on Critical severity)     │
                    └──────────────────────────────────┘
```

---

## Features

| Feature | Description | Feature Flag |
|---------|-------------|-------------|
| Sentinel | Real-time attack detection pipeline | `sentinel` (default) |
| Autopsy Lab | Post-hack forensic analysis | `autopsy` (default) |
| Time-Travel Debugger | Interactive opcode replay | always included |
| CLI | Interactive debugger shell | `cli` |
| Dashboard | Web UI for Sentinel metrics | `sentinel` |
| AI Agent | LLM-assisted attack verification (Phase 1 MVP complete — 2-tier judge, hallucination guard, cost tracking) | `ai_agent` |

---

## Building

```bash
# Default (Sentinel + Autopsy)
cargo build

# With CLI debugger
cargo build --features cli

# All features
cargo build --all-features
```

**Requirements**: Rust 1.85+ (edition 2024)

### Docker

```bash
# Pull pre-built image
docker pull tokamak/argus-demo:latest

# Run Sentinel on mainnet
docker run -d \
  -e ARGUS_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  -p 9090:9090 \
  tokamak/argus-demo:latest

# Or build and run locally (runs sentinel in prefilter-only mode)
docker build -t argus-demo .
docker run -e ARGUS_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" argus-demo
```

### Configuration

Copy the example config and adjust for your setup:

```bash
cp sentinel.toml.example sentinel.toml
# The argus binary requires the `cli` feature flag
cargo build --release --features cli
cargo run --release --features cli -- sentinel \
  --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --config sentinel.toml
```

See [`sentinel.toml.example`](sentinel.toml.example) for all available options with inline documentation.

For production deployment on AWS ECS Fargate, see [Deployment Guide](docs/deployment.md).

---

## Powered By

Argus uses [ethrex](https://github.com/lambdaclass/ethrex) LEVM as its EVM execution engine — a minimal, fast Ethereum Virtual Machine implementation in Rust. Argus depends on [Tokamak Network's fork](https://github.com/tokamak-network/ethrex) which includes the `tokamak-debugger` feature.

---

## Contributors

Currently maintained by [Jason Hwang](https://github.com/nicewook) with AI-assisted development. Looking for contributors — see [CONTRIBUTING.md](CONTRIBUTING.md) to get started!

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

Built by [Tokamak Network](https://tokamak.network/).
