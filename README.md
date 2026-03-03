# Argus

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

This simulates a block containing both benign and malicious transactions, showing Sentinel's detection pipeline in action.

### Run the Autopsy demo

```bash
cargo run --example reentrancy_demo
```

Deploys a vulnerable contract, executes a reentrancy attack, and generates a full forensic report.

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

---

## Powered By

Argus uses [ethrex](https://github.com/lambdaclass/ethrex) LEVM as its EVM execution engine — a minimal, fast Ethereum Virtual Machine implementation in Rust.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).

Built by [Tokamak Network](https://tokamak.network/).
