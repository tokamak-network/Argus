# Argus Holesky Deployment Guide

Run Argus Sentinel on the Holesky testnet for 14 days to validate detection performance before mainnet.

## Prerequisites

- **Ethereum RPC endpoint** with Holesky access — [Alchemy](https://alchemy.com), [Infura](https://infura.io), or a self-hosted node
  - `--prefilter-only` mode: any full node (standard JSON-RPC)
  - Deep opcode replay mode: archive node required
- **Docker** 24+ _or_ **Rust 1.85+** (for native build)
- Outbound HTTP access on port 9090 (metrics)

## Quick Start — Docker

```bash
# Pull the pre-built image
docker pull tokamak-network/argus:v0.1.0

# Run in prefilter-only mode (works with any full node)
docker run -d \
  --name argus-holesky \
  -e ARGUS_RPC_URL="https://eth-holesky.g.alchemy.com/v2/YOUR_KEY" \
  -e ARGUS_METRICS_PORT="9090" \
  -p 9090:9090 \
  tokamak-network/argus:v0.1.0

# Stream logs
docker logs -f argus-holesky

# Check health
curl http://localhost:9090/health
```

To save alerts to a file:

```bash
docker run -d \
  --name argus-holesky \
  -e ARGUS_RPC_URL="https://eth-holesky.g.alchemy.com/v2/YOUR_KEY" \
  -e ARGUS_METRICS_PORT="9090" \
  -p 9090:9090 \
  -v $(pwd)/alerts:/data \
  tokamak-network/argus:v0.1.0 \
  "exec argus sentinel --rpc \"$ARGUS_RPC_URL\" --metrics-port \"$ARGUS_METRICS_PORT\" --alert-file /data/alerts.jsonl --prefilter-only"
```

## Quick Start — Native

```bash
# Clone and build
git clone https://github.com/tokamak-network/Argus.git
cd Argus
cargo build --release --features cli --bin argus

# Run against Holesky
./target/release/argus sentinel \
  --rpc-url "https://eth-holesky.g.alchemy.com/v2/YOUR_KEY" \
  --alert-file alerts.jsonl \
  --metrics-port 9090 \
  --poll-interval 2 \
  --prefilter-only
```

For deep opcode replay (archive node required):

```bash
./target/release/argus sentinel \
  --rpc-url "https://eth-holesky.g.alchemy.com/v2/YOUR_KEY" \
  --alert-file alerts.jsonl \
  --metrics-port 9090 \
  --poll-interval 2
```

## Configuration

CLI flags take precedence over the config file. Pass `--config sentinel.toml` to load defaults from a file:

```toml
# sentinel.toml — example Holesky configuration

[prefilter]
suspicion_threshold = 0.5     # 0.0–1.0; lower = more alerts
min_value_eth       = 1.0     # ignore transfers below this ETH value
min_gas_used        = 500000  # ignore low-gas transactions
min_erc20_transfers = 5       # flag txs with many token transfers
gas_ratio_threshold = 0.95    # flag near-block-limit gas usage

[analysis]
max_steps             = 1000000  # max opcode steps per replay
min_alert_confidence  = 0.4      # 0.0–1.0
prefilter_alert_mode  = true     # emit alerts from pre-filter when no archive node

[alert]
rate_limit_per_minute  = 30   # suppress bursts
dedup_window_blocks    = 10   # suppress duplicate alerts within N blocks

[auto_pause]
confidence_threshold = 0.9    # pause sentinel if alert confidence exceeds this
```

Load it:

```bash
argus sentinel --rpc-url "..." --config sentinel.toml --metrics-port 9090
```

## Monitoring

### Prometheus scrape

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: argus
    static_configs:
      - targets: ["localhost:9090"]
```

Then scrape `http://localhost:9090/metrics`. Key counters:

| Metric | Description |
|--------|-------------|
| `sentinel_blocks_scanned` | Total Holesky blocks processed |
| `sentinel_txs_scanned` | Total transactions seen by pre-filter |
| `sentinel_txs_flagged` | Transactions flagged as suspicious |
| `sentinel_alerts_emitted` | Alerts confirmed by deep analysis |
| `sentinel_alerts_deduplicated` | Alerts suppressed by dedup |
| `sentinel_alerts_rate_limited` | Alerts suppressed by rate limiter |
| `sentinel_prefilter_total_us` | Cumulative pre-filter time (μs) |
| `sentinel_deep_analysis_total_ms` | Cumulative deep analysis time (ms) |

### Health check

```bash
curl -s http://localhost:9090/health | jq .
# {
#   "status": "running",
#   "blocks_scanned": 12345,
#   "txs_scanned": 678901,
#   "alerts_emitted": 5,
#   "uptime_secs": 86400
# }
```

## 14-Day Run Checklist

### Day 0 — Setup

- [ ] RPC endpoint confirmed working (`curl -X POST -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' $RPC_URL`)
- [ ] Argus running, health endpoint responds `"status": "running"`
- [ ] Alert file or webhook configured
- [ ] Prometheus scraping (optional but recommended)

### Days 1–3 — Baseline

- [ ] `sentinel_blocks_scanned` incrementing steadily (~30 blocks/min on Holesky)
- [ ] No error-rate spikes in logs
- [ ] Confirm false-positive rate is acceptable (tune `suspicion_threshold` if needed)

### Days 4–7 — Stability

- [ ] Check for RPC rate-limit errors (see Troubleshooting)
- [ ] Verify alert deduplication is working (watch `sentinel_alerts_deduplicated`)
- [ ] Snapshot metrics: record `sentinel_txs_scanned` and `sentinel_txs_flagged`

### Days 8–12 — Performance

- [ ] Average pre-filter latency: `sentinel_prefilter_total_us / sentinel_txs_scanned` < 50μs target
- [ ] Average deep analysis: `sentinel_deep_analysis_total_ms / sentinel_alerts_emitted`
- [ ] Review alert file for quality (are flagged TXs genuinely suspicious?)

### Day 13–14 — Results

- [ ] Final snapshot of all metrics
- [ ] Calculate flag rate: `sentinel_txs_flagged / sentinel_txs_scanned`
- [ ] Calculate confirmation rate: `sentinel_alerts_emitted / sentinel_txs_flagged`
- [ ] Archive alert JSONL for offline review

## Interpreting Results

After 14 days, generate a summary for the README:

```bash
# Extract final counts from health endpoint
curl -s http://localhost:9090/health | jq '{
  blocks: .blocks_scanned,
  txs: .txs_scanned,
  alerts: .alerts_emitted,
  days: (.uptime_secs / 86400 | floor)
}'
```

Use these numbers to fill in the README performance table:

> "Monitored **{blocks}** Holesky blocks ({txs} transactions) over **{days} days**.
> Pre-filter flagged **{flagged}** transactions; deep analysis confirmed **{alerts}** alerts."

A healthy run shows:
- Flag rate < 1% of all txs (pre-filter isn't too noisy)
- Confirmation rate > 20% (deep analysis is meaningful)
- Zero crashes or missed blocks over 14 days

## Troubleshooting

### RPC rate limit errors

Symptoms: logs show `429 Too Many Requests` or `rate limit exceeded`.

```bash
# Increase poll interval to reduce RPC calls
argus sentinel --rpc-url "..." --poll-interval 5

# Or upgrade your RPC plan (Alchemy free tier: 300M compute units/month)
```

### Connection drops / timeouts

Symptoms: logs show `connection reset` or `timeout` errors; `sentinel_blocks_scanned` stops incrementing.

Argus retries transient RPC errors automatically. If drops are frequent:

1. Check RPC endpoint uptime
2. Try a backup RPC endpoint
3. Reduce `--poll-interval` to avoid long-idle connection resets

### No alerts after 24h

On Holesky, attack patterns are rare. Expected behavior in `--prefilter-only` mode:
- `sentinel_txs_flagged` should be non-zero (pre-filter is working)
- `sentinel_alerts_emitted` may be 0 (no confirmed attacks — this is fine on testnet)

Lower `suspicion_threshold` in `sentinel.toml` to 0.3 to see more pre-filter flags.

### Binary not found (Docker)

```bash
# Verify the argus binary exists in the image
docker run --rm --entrypoint which tokamak-network/argus:v0.1.0 argus

# Run sentinel --help to check CLI is working
docker run --rm tokamak-network/argus:v0.1.0 "argus sentinel --help"
```
