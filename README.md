# Argus

[![CI](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml/badge.svg)](https://github.com/tokamak-network/Argus/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

**The Hundred-Eyed Guardian for Ethereum**

Real-time attack detection, post-hack forensics, and time-travel debugging for EVM transactions.

> Existing security tools (Slither, Mythril, Echidna) analyze contracts **before** deployment.
> Argus protects **after** deployment — detecting attacks as they happen and analyzing them when they've already occurred.

---

## What Argus Does

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

## Real-World Case Study

**[How Argus Would Have Detected the $128M Balancer V2 Exploit](docs/analysis-balancer-v2-exploit.md)**

On November 3, 2025, an attacker exploited a rounding error in Balancer V2's `batchSwap` to drain $128M across 6 chains in under 30 minutes. The community didn't notice for 42 minutes.

Argus's Sentinel would have:
1. **Pre-filter**: Flagged the transaction in the mempool (3M gas + 4.2KB calldata + Balancer Vault interaction)
2. **Deep Analyzer**: Classified as price manipulation (82% confidence) after opcode replay
3. **Auto-pause**: Halted block processing within seconds of the first attack transaction
4. **Autopsy**: Generated a full forensic report with fund flow tracing

Read the full analysis: [docs/analysis-balancer-v2-exploit.md](docs/analysis-balancer-v2-exploit.md)

### [How Argus Would Have Detected the $1.5B Bybit Exploit](docs/analysis-bybit-1.4b-exploit.md)

On February 21, 2025, North Korea's Lazarus Group executed the largest crypto theft in history — $1.5B drained from Bybit's cold wallet via a supply chain attack on Safe{Wallet}'s front-end.

Argus's Sentinel would have:
1. **Pre-filter**: Flagged the transaction for unusual DELEGATECALL to an unverified contract
2. **Deep Analyzer**: Classified as access control bypass (95% confidence) — proxy implementation overwritten
3. **Auto-pause**: Halted block processing within seconds
4. **Autopsy**: Traced fund flow across 40+ intermediary wallets

Read the full analysis: [docs/analysis-bybit-1.4b-exploit.md](docs/analysis-bybit-1.4b-exploit.md)

---

## How It Compares

| | Argus | Forta | OpenZeppelin Defender | Tenderly |
|---|---|---|---|---|
| Runtime detection | Yes | Yes (bot network) | Yes (monitors) | Partial (alerts) |
| L1 node integration | **Yes** | No | No | No |
| Mempool pre-detection | **Yes** | No | No | No |
| Auto-pause circuit breaker | **Yes** | No | No | No |
| Post-hack forensics | **Yes** | No | No | Partial |
| Attack classification | **Automatic** | Bot-dependent | Manual rules | Manual |
| Open source | **Fully** | Partial | No | No |
| Self-hosted | **Yes** | No (SaaS) | No (SaaS) | No (SaaS) |

---

## Architecture

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
# Run the Sentinel demo
docker run tokamak/argus-demo

# Run the Autopsy demo
docker run tokamak/argus-demo reentrancy_demo

# Run the Dashboard demo
docker run tokamak/argus-demo sentinel_dashboard_demo
```

---

## Powered By

Argus uses [ethrex](https://github.com/lambdaclass/ethrex) LEVM as its EVM execution engine — a minimal, fast Ethereum Virtual Machine implementation in Rust.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

Built by [Tokamak Network](https://tokamak.network/).
