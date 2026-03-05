# Argus

[![CI](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml/badge.svg)](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

**The Hundred-Eyed Guardian for Ethereum**

Real-time attack detection, post-hack forensics, and time-travel debugging for EVM transactions.

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
   Critical alert → block processing HALTED
```

> No RPC key needed — demos run against local LEVM. Try it in 30 seconds:
> `git clone https://github.com/tokamak-network/Argus.git && cd Argus && cargo run --example sentinel_realtime_demo`

---

## What Argus Does

> All features below have been implemented and tested. Argus is currently running on **Ethereum mainnet** via AWS ECS Fargate — see [Deployment Guide](docs/deployment.md) and [Roadmap](docs/ROADMAP.md).

### Sentinel — Real-Time Attack Detection

A 2-stage detection pipeline integrated at the block processing level:

- **Pre-filter**: Receipt-based heuristics (~10-50μs/tx) eliminate 99% of benign transactions
- **Deep analyzer**: Full opcode-level replay on suspicious transactions only
- **Mempool monitoring**: Detect attacks *before* they're included in a block
- **Auto-pause circuit breaker**: Automatically halt processing on critical alerts
- **Multi-channel alerts**: JSONL, Webhook (Slack/Discord/PagerDuty), WebSocket, Prometheus

### Autopsy Lab — Post-Hack Forensics

Replay any mainnet transaction and generate a forensic report:

- **Attack pattern classification**: Reentrancy, flash loans, price oracle manipulation, access control bypasses
- **Fund flow tracing**: Track ETH and ERC-20 token movements through the attack
- **Markdown report generation**: Structured timeline with attack phases, evidence, and suggested fixes

### Time-Travel Debugger

GDB-style interactive replay at opcode granularity:

- Forward/backward stepping through execution
- Breakpoints on opcode, address, or storage slot
- Full state inspection at any point in execution
- Sub-50ms step navigation

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

Deploys a vulnerable contract, executes a reentrancy attack, and generates a full forensic report:

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

Phase 5  SentinelService Pipeline
  Alert Priority: Critical
  Score: 0.85
  Summary: Likely reentrancy attack (confidence: 90%)
```

---

## Case Studies — Retroactive Analysis

> **Note:** These are retroactive analyses of past exploits, not real-time detections from the live pipeline. Argus is currently scanning Ethereum mainnet via AWS ECS Fargate (since March 2026). We include these to demonstrate the detection logic on known exploits.

**[Retroactive Analysis: $128M Balancer V2 Exploit](docs/analysis-balancer-v2-exploit.md)**

On November 3, 2025, an attacker exploited a rounding error in Balancer V2's `batchSwap` to drain $128M across 6 chains in under 30 minutes. We analyzed this transaction through Argus's detection pipeline:

1. **Pre-filter**: Flags the transaction pattern (3M gas + 4.2KB calldata + Balancer Vault interaction)
2. **Deep Analyzer**: Classifies as price manipulation (82% confidence) after opcode replay
3. **Autopsy**: Generates a forensic report with fund flow tracing

Read the full analysis: [docs/analysis-balancer-v2-exploit.md](docs/analysis-balancer-v2-exploit.md)

**[Retroactive Analysis: $1.5B Bybit Exploit](docs/analysis-bybit-1.4b-exploit.md)**

On February 21, 2025, North Korea's Lazarus Group executed the largest crypto theft in history — $1.5B drained from Bybit's cold wallet via a supply chain attack on Safe{Wallet}'s front-end.

1. **Pre-filter**: Flags the transaction for unusual DELEGATECALL to an unverified contract
2. **Deep Analyzer**: Classifies as access control bypass (95% confidence) — proxy implementation overwritten
3. **Autopsy**: Traces fund flow across 40+ intermediary wallets

Read the full analysis: [docs/analysis-bybit-1.4b-exploit.md](docs/analysis-bybit-1.4b-exploit.md)

---

## How It Compares

| | Argus | Forta | Phalcon | Tenderly | Hexagate |
|---|---|---|---|---|---|
| Runtime detection | Yes | Yes (bot network) | Yes | Partial (alerts) | Yes |
| Mempool pre-detection | Yes | No | Yes | Yes | Yes |
| Post-hack forensics | **Yes** | No | No | Partial | No |
| Open source | **Fully** | Partial | No | No | No |
| Self-hosted | **Yes** | No (SaaS) | No (SaaS) | No (SaaS) | No (SaaS) |
| Multi-chain | No | Yes (7+) | Yes | Yes (109) | Yes |
| Production track record | **Mainnet scanning (since Mar 2026)** | 270M+ TX scanned | 20+ hacks blocked | 1.4M+ simulations | Undisclosed |

> Argus is early-stage but running on Ethereum mainnet via AWS ECS Fargate. 14-day validation: ~100K blocks, ~20M TXs scanned, zero downtime, $7/month — see [operations report](docs/mainnet-report-march-2026.md). Its primary differentiator is being **fully open-source and self-hostable**. See [competitive analysis](docs/competitive-analysis.md) for an honest, detailed comparison.

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
docker pull tokamak-network/argus:v0.1.3

# Run Sentinel on mainnet
docker run -d \
  -e ARGUS_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  -p 9090:9090 \
  tokamak-network/argus:v0.1.3

# Or build locally
docker build -t argus-demo .
docker run argus-demo
```

### Configuration

Copy the example config and adjust for your setup:

```bash
cp sentinel.toml.example sentinel.toml
argus sentinel --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --config sentinel.toml
```

See [`sentinel.toml.example`](sentinel.toml.example) for all available options with inline documentation.

For production deployment on AWS ECS Fargate, see [Deployment Guide](docs/deployment.md).

---

## Powered By

Argus uses [ethrex](https://github.com/lambdaclass/ethrex) LEVM as its EVM execution engine — a minimal, fast Ethereum Virtual Machine implementation in Rust. Argus depends on [Tokamak Network's fork](https://github.com/tokamak-network/ethrex) which includes the `tokamak-debugger` feature.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

Built by [Tokamak Network](https://tokamak.network/).
