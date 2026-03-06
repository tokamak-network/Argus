# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SECURITY.md vulnerability disclosure policy
- CHANGELOG.md following Keep a Changelog format
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- GitHub issue and PR templates
- Dependabot configuration for Cargo and GitHub Actions

## [0.1.3] - 2026-03-05

### Added
- Batch receipt fetch via `eth_getBlockReceipts` with per-receipt fallback
- `flash_loan_ranges_overlap` tests for improved pre-filter scoring coverage
- Phase 2 deliverables: replay benchmark, latency bench, mainnet detection report
- AI Agent Phase 1 MVP: 2-tier LLM pipeline for EVM attack detection (feature: `ai_agent`)
- DeFi whitelist engine for false-positive reduction
- Sentinel dashboard full redesign (Astro + React + Recharts)

### Changed
- Pre-filter test suite split into two focused modules
- Pre-filter scoring model improvements

### Fixed
- Fallback error handling improvements (devil review)
- `detected_patterns` and `fund_flows` population in RPC-mode deep alerts

## [0.1.2] - 2026-03-04

### Fixed
- TX hash mismatch bug: use RPC original hash instead of ethrex RLP recalculation

### Added
- Dual-RPC mode (polling on free node, deep replay on archive node)
- Mainnet deployment documentation and ECS deploy script

## [0.1.1] - 2026-03-04

### Fixed
- Config loading bug: `_config` renamed to `config` so TOML settings are actually applied

### Added
- `argus sentinel` CLI subcommand with `--rpc`, `--config`, `--alert-file`, `--metrics-port`
- HTTP metrics/health server (Prometheus `/metrics`, JSON `/health`)
- Improved Autopsy CLI with DRY refactor, aliases, and interactive mode

## [0.1.0] - 2026-02-28

### Added
- **ReplayEngine**: time-travel EVM debugger with step-forward, step-back, jump-to-step, breakpoints, and watchpoints
- **DebugRecorder**: opcode-level execution capture integrated with ethrex LEVM
- **Sentinel pipeline**: real-time attack detection
  - Pre-filter heuristics (10-50us per transaction)
  - Deep opcode-level analyzer
  - Alert dispatcher with deduplication and rate limiting
  - WebSocket broadcaster for streaming alerts
  - Prometheus-compatible metrics endpoint
  - Slack, Discord, and PagerDuty webhook integration
  - Circuit breaker (auto-pause) for safety
  - Statistical anomaly detection (ML model)
  - TOML-based configuration
- **Autopsy forensics**: post-hack analysis
  - Attack pattern classifier (reentrancy, flash loan, price manipulation)
  - ETH/ERC-20 fund flow tracing
  - ABI function and event decoding
  - Contract label enrichment
  - Markdown report generation
- **CLI debugger**: GDB-style interactive debugger (`--features cli`)
- Docker image published to Docker Hub
- 5 runnable example demos
- 767 tests (+ 27 ignored requiring RPC/AI API)
- GitHub Actions CI (check, test, clippy, fmt)

[Unreleased]: https://github.com/tokamak-network/Argus/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/tokamak-network/Argus/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/tokamak-network/Argus/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/tokamak-network/Argus/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/tokamak-network/Argus/releases/tag/v0.1.0
