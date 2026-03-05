#!/usr/bin/env bash
# Record an asciinema demo of Argus Sentinel + Autopsy.
#
# Prerequisites:
#   brew install asciinema    # macOS
#   pip install asciinema     # or pip
#
# Usage:
#   ./scripts/record-demo.sh            # record to demo.cast
#   ./scripts/record-demo.sh upload     # record + upload to asciinema.org
#
# Convert to GIF (optional):
#   npm install -g svg-term-cli
#   svg-term --in demo.cast --out demo.svg --window --width 80 --height 24

set -euo pipefail

CAST_FILE="${CAST_FILE:-demo.cast}"
COLS=100
ROWS=30

echo "=== Argus Demo Recording ==="
echo "Output: ${CAST_FILE}"
echo ""

# Check prerequisites
if ! command -v asciinema &>/dev/null; then
  echo "Error: asciinema not found. Install with: brew install asciinema"
  exit 1
fi

if ! command -v cargo &>/dev/null; then
  echo "Error: cargo not found. Install Rust: https://rustup.rs"
  exit 1
fi

# Build first to avoid recording compile time
echo "Building Argus (this may take a moment)..."
cargo build --example sentinel_realtime_demo --example reentrancy_demo --quiet 2>/dev/null || \
  cargo build --example sentinel_realtime_demo --example reentrancy_demo

echo ""
echo "Starting recording. Run these commands in the session:"
echo "  1) cargo run --example sentinel_realtime_demo"
echo "  2) cargo run --example reentrancy_demo"
echo "  3) exit"
echo ""

# Record
asciinema rec "${CAST_FILE}" \
  --cols "${COLS}" \
  --rows "${ROWS}" \
  --title "Argus — Ethereum Attack Detection" \
  --idle-time-limit 3

echo ""
echo "Recording saved to ${CAST_FILE}"

# Optional upload
if [[ "${1:-}" == "upload" ]]; then
  echo "Uploading to asciinema.org..."
  asciinema upload "${CAST_FILE}"
fi
