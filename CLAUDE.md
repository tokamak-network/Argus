# Argus — Development Guide

## What Is This?

Ethereum real-time attack detection + post-hack forensics + time-travel debugger.
Built with Rust, powered by ethrex LEVM.

## Build Commands

```bash
cargo check                                    # Compile check
cargo test                                     # Run 283 tests
cargo clippy --all-features -- -D warnings     # Lint (warnings = errors)
cargo fmt --check                              # Format check

# Examples
cargo run --example sentinel_realtime_demo     # Sentinel pipeline demo
cargo run --example reentrancy_demo            # Reentrancy attack demo
cargo run --example sentinel_dashboard_demo    # Dashboard integration demo

# CLI debugger
cargo run --bin argus --features cli

# Docker
docker build -t argus-demo .
docker run argus-demo
```

**Rust 1.85+ required** (edition 2024).

## Architecture

```
src/
├── lib.rs              # Module exports
├── engine.rs           # ReplayEngine — time-travel navigation
├── recorder.rs         # DebugRecorder — opcode step capture
├── types.rs            # ReplayTrace, StepRecord, ReplayConfig
├── error.rs            # DebuggerError, RpcError
├── sentinel/           # Real-time detection (8,756 LoC)
│   ├── types.rs        #   Alert types, SuspicionReason
│   ├── pre_filter.rs   #   Receipt heuristics (~10-50μs/tx)
│   ├── pipeline.rs     #   Adaptive multi-step analysis
│   ├── analyzer.rs     #   Deep opcode-level analyzer
│   ├── alert.rs        #   Dispatcher, dedup, rate limiter
│   ├── service.rs      #   Background worker thread
│   ├── mempool_filter.rs   Pre-execution calldata scan
│   ├── webhook.rs      #   Slack/Discord/PagerDuty
│   ├── ws_broadcaster.rs  WebSocket streaming
│   ├── auto_pause.rs   #   Circuit breaker
│   ├── ml_model.rs     #   Statistical anomaly detection
│   ├── metrics.rs      #   Prometheus-compatible
│   ├── history.rs      #   Alert history storage
│   └── config.rs       #   TOML config parsing
├── autopsy/            # Post-hack forensics (3,544 LoC)
│   ├── types.rs        #   AttackPattern, FundFlow
│   ├── classifier.rs   #   Reentrancy, flash loan, price manipulation
│   ├── fund_flow.rs    #   ETH/ERC-20 transfer tracing
│   ├── report.rs       #   Markdown report generation
│   ├── rpc_client.rs   #   Archive node RPC with retry
│   ├── abi_decoder.rs  #   Function/event decoding
│   └── enrichment.rs   #   Contract label enrichment
├── cli/                # Interactive GDB-style debugger
└── tests/              # Test suite (283 tests)

dashboard/              # Web UI (Astro + React + Recharts)
examples/               # 3 runnable demos
docs/                   # Case studies
```

## Feature Flags

| Feature | Default | What It Adds |
|---------|---------|-------------|
| `sentinel` | Yes | Real-time detection pipeline, axum, tokio |
| `autopsy` | Yes | Forensic analysis, reqwest, sha3 |
| `cli` | No | Interactive debugger shell, clap, rustyline |

## Key Dependencies

- **ethrex LEVM**: EVM execution engine (git dep, rev `03fc1858`)
- **axum**: HTTP/WebSocket server (Sentinel)
- **reqwest**: RPC client (Autopsy)
- **tokio**: Async runtime (Sentinel)

## Detection Pipeline

```
Mempool → Pre-Filter (10-50μs) → Deep Analyzer (opcode replay) → Alert Dispatcher
                                                                      │
                                              ┌───────────────────────┼────────┐
                                              │        │        │     │        │
                                           JSONL   Webhook    WS  Prometheus  Auto-Pause
```

## Coding Conventions

- **Rust edition 2024** — use latest language features
- **Clippy warnings = errors** in CI (`-D warnings`)
- Tests go in `src/tests/` (integration) or inline `#[cfg(test)]`
- Error types use `thiserror` derive macros
- Retryable vs permanent errors distinguished via `is_retryable()`
- Feature-gated modules: `#[cfg(feature = "...")]`

## CI

GitHub Actions runs on every push/PR to `main`:
1. `cargo check --all-features`
2. `cargo test --all-features`
3. `cargo clippy --all-features -- -D warnings`
4. `cargo fmt --check`

## ethrex Dependency

Uses git dependency pinned to rev `03fc1858`:
```toml
ethrex-levm = { git = "https://github.com/tokamak-network/ethrex", rev = "03fc1858", features = ["tokamak-debugger"] }
```

To update: change `rev` in Cargo.toml, run `cargo update`, verify all tests pass.
