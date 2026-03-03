# Contributing to Argus

Thank you for considering contributing to Argus. Every contribution matters — bug reports, documentation fixes, and code improvements alike.

## Quick Start

```bash
# Clone and build
git clone https://github.com/tokamak-network/Argus.git
cd Argus
cargo build --all-features

# Run tests
cargo test --all-features

# Run a demo
cargo run --example sentinel_realtime_demo
```

**Requirements**: Rust 1.85+ (edition 2024)

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/tokamak-network/Argus/issues) with:
- What you expected vs what happened
- Steps to reproduce
- Rust version (`rustc --version`)

### Suggesting Features

Open an issue with the `enhancement` label. Describe the use case, not just the solution.

### Submitting Code

1. Fork the repo and create a branch from `main`
2. Write your changes
3. Ensure all checks pass:
   ```bash
   cargo check --all-features
   cargo test --all-features
   cargo clippy --all-features -- -D warnings
   cargo fmt --check
   ```
4. Open a Pull Request with a clear description

### Good First Issues

Look for issues labeled [`good first issue`](https://github.com/tokamak-network/Argus/labels/good%20first%20issue). These are scoped tasks suitable for newcomers.

Areas where contributions are especially welcome:
- **Mainnet TX test fixtures** — Add real mainnet attack transactions as test data
- **Attack pattern heuristics** — New detection rules for Sentinel pre-filter
- **Dashboard components** — React components for the monitoring UI
- **Documentation** — Tutorials, API docs, architecture explanations

## Code Style

- **Clippy warnings = errors** in CI (`-D warnings`)
- **Edition 2024** — use latest Rust features
- Error types use `thiserror` derive macros
- Feature-gated modules: `#[cfg(feature = "...")]`
- Tests in `src/tests/` (integration) or inline `#[cfg(test)]`

## Project Structure

```
src/
├── sentinel/    # Real-time detection (feature: sentinel)
├── autopsy/     # Post-hack forensics (feature: autopsy)
├── cli/         # Interactive debugger (feature: cli)
├── engine.rs    # Time-travel replay engine
├── recorder.rs  # Opcode step recorder
└── tests/       # Integration tests

examples/        # Runnable demos
dashboard/       # Web UI (Astro + React)
```

## License

By contributing, you agree that your contributions will be dual-licensed under MIT and Apache 2.0.
