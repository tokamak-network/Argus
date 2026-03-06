# Argus Deployment Guide

Run Argus Sentinel on Ethereum mainnet (or any EVM chain) to detect attacks in real time.

## Deployment Options

| Method | Best For | Infra Management |
|--------|----------|-----------------|
| [Docker (local)](#docker-local) | Quick test, dev environment | You manage |
| [Native binary](#native-binary) | Custom builds, CI integration | You manage |
| [AWS ECS Fargate](#aws-ecs-fargate) | Production, long-running | Serverless (AWS) |

---

## Prerequisites

- **Ethereum RPC endpoint** — [Alchemy](https://alchemy.com), [Infura](https://infura.io), or a self-hosted node
  - `--prefilter-only` mode: any full node (standard JSON-RPC)
  - Deep opcode replay mode: archive node required
- Outbound HTTPS (RPC calls) + inbound TCP 9090 (metrics/health)

---

## Docker (local)

```bash
# Pull the pre-built image
docker pull tokamak/argus-demo:latest

# Run in prefilter-only mode (works with any full node)
docker run -d \
  --name argus-sentinel \
  -e ARGUS_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  -e ARGUS_METRICS_PORT="9090" \
  -p 9090:9090 \
  tokamak/argus-demo:latest

# Stream logs
docker logs -f argus-sentinel

# Check health
curl http://localhost:9090/health
```

To save alerts to a file:

```bash
docker run -d \
  --name argus-sentinel \
  -e ARGUS_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  -e ARGUS_METRICS_PORT="9090" \
  -p 9090:9090 \
  -v $(pwd)/alerts:/data \
  tokamak/argus-demo:latest \
  "exec argus sentinel --rpc \"$ARGUS_RPC_URL\" --metrics-port \"$ARGUS_METRICS_PORT\" --alert-file /data/alerts.jsonl --prefilter-only"
```

---

## Native Binary

```bash
# Clone and build
git clone https://github.com/tokamak-network/Argus.git
cd Argus
cargo build --release --features cli --bin argus

# Run prefilter-only (any full node)
./target/release/argus sentinel \
  --rpc "https://eth.llamarpc.com" \
  --alert-file alerts.jsonl \
  --metrics-port 9090 \
  --poll-interval 2 \
  --prefilter-only

# Run with deep analysis — dual RPC (recommended)
# Polling on free public node, deep replay on Alchemy archive
./target/release/argus sentinel \
  --rpc "https://eth.llamarpc.com" \
  --archive-rpc "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  --alert-file alerts.jsonl \
  --metrics-port 9090 \
  --config sentinel.toml

# Run with single RPC (archive node required for both polling and replay)
./target/release/argus sentinel \
  --rpc "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  --alert-file alerts.jsonl \
  --metrics-port 9090 \
  --config sentinel.toml
```

**Requirements**: Rust 1.85+ (edition 2024)

---

## AWS ECS Fargate

Serverless deployment — no EC2 instances to manage. Argus runs as a Fargate task with automatic log shipping to CloudWatch.

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌─────────────────┐
│ Secrets       │     │ ECR          │     │ CloudWatch Logs │
│ Manager       │     │ argus:v0.1.3 │     │ /ecs/argus-     │
│ (RPC URL)     │     │              │     │  sentinel       │
└──────┬───────┘     └──────┬───────┘     └────────▲────────┘
       │                    │                      │
       ▼                    ▼                      │
┌──────────────────────────────────────────────────┐
│              ECS Fargate Task                     │
│  ┌──────────────────────────────────────────┐    │
│  │  argus sentinel --rpc $RPC_URL           │    │
│  │  --config /tmp/sentinel.toml             │────┘
│  │  --metrics-port 9090                     │
│  └──────────────────────────────────────────┘    │
│              :9090 (health + metrics)             │
└──────────────────────────────────────────────────┘
```

### Step 1: ECR Repository

```bash
aws ecr create-repository --repository-name argus --region ap-northeast-2
```

### Step 2: Build & Push Image

```bash
# Build for linux/amd64 (Fargate requires x86_64)
docker buildx build --platform linux/amd64 -t argus:v0.1.3 .

# Login to ECR
aws ecr get-login-password --region ap-northeast-2 | \
  docker login --username AWS --password-stdin \
  <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com

# Tag & push
docker tag argus:v0.1.3 <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/argus:v0.1.3
docker push <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/argus:v0.1.3
```

### Step 3: Store RPC URL in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name argus/rpc-url \
  --secret-string "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  --region ap-northeast-2
```

### Step 4: IAM Role

Create `argus-ecs-execution-role` with these policies:

- `AmazonECSTaskExecutionRolePolicy` (ECR pull)
- Secrets Manager read access for `argus/rpc-url`
- CloudWatch Logs: `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`

### Step 5: Security Group

```bash
aws ec2 create-security-group \
  --group-name argus-sentinel-sg \
  --description "Argus Sentinel ECS"

# Inbound: metrics/health (restrict to your VPC CIDR or monitoring IP)
aws ec2 authorize-security-group-ingress \
  --group-id <SG_ID> --protocol tcp --port 9090 --cidr 10.0.0.0/16

# WARNING: Do NOT use 0.0.0.0/0 — the metrics endpoint exposes operational
# data and has no authentication. Restrict to your VPC CIDR, monitoring
# subnet, or specific IPs. See SECURITY.md for guidance.

# Outbound: all (RPC calls — default allows all)
```

### Step 6: ECS Cluster & Task Definition

```bash
aws ecs create-cluster --cluster-name argus --region ap-northeast-2
```

Task definition (`task-def.json`):

```json
{
  "family": "argus-sentinel",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<ACCOUNT_ID>:role/argus-ecs-execution-role",
  "containerDefinitions": [
    {
      "name": "argus",
      "image": "<ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/argus:v0.1.3",
      "essential": true,
      "command": [
        "printf '[sentinel]\\nenabled = true\\n\\n[sentinel.prefilter]\\nsuspicion_threshold = 0.7\\nmin_value_eth = 1.0\\nmin_erc20_transfers = 20\\ngas_ratio_threshold = 0.98\\n\\n[sentinel.analysis]\\nmax_steps = 500000\\nmin_alert_confidence = 0.6\\nprefilter_alert_mode = false\\n\\n[sentinel.alert]\\nrate_limit_per_minute = 10\\ndedup_window_blocks = 5\\n' > /tmp/sentinel.toml && exec argus sentinel --rpc \"$ARGUS_RPC_URL\" --metrics-port \"$ARGUS_METRICS_PORT\" --config /tmp/sentinel.toml"
      ],
      "portMappings": [{ "containerPort": 9090, "protocol": "tcp" }],
      "secrets": [
        {
          "name": "ARGUS_RPC_URL",
          "valueFrom": "arn:aws:secretsmanager:ap-northeast-2:<ACCOUNT_ID>:secret:argus/rpc-url-XXXXXX"
        }
      ],
      "environment": [
        { "name": "ARGUS_METRICS_PORT", "value": "9090" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/argus-sentinel",
          "awslogs-region": "ap-northeast-2",
          "awslogs-stream-prefix": "argus",
          "awslogs-create-group": "true"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://task-def.json --region ap-northeast-2
```

### Step 7: Create Service

```bash
aws ecs create-service \
  --cluster argus \
  --service-name argus-sentinel \
  --task-definition argus-sentinel \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_ID>],securityGroups=[<SG_ID>],assignPublicIp=ENABLED}" \
  --region ap-northeast-2
```

### Step 8: Verify

```bash
# Get task IP
TASK_ARN=$(aws ecs list-tasks --cluster argus --service-name argus-sentinel \
  --query 'taskArns[0]' --output text --region ap-northeast-2)

TASK_IP=$(aws ecs describe-tasks --cluster argus --tasks $TASK_ARN \
  --query 'tasks[0].attachments[0].details[?name==`privateIPv4Address`].value' \
  --output text --region ap-northeast-2)

# Health check (from within VPC or via SSH bastion)
curl http://$TASK_IP:9090/health
```

### Updating the Image

```bash
# Build, tag, push new version
docker buildx build --platform linux/amd64 -t argus:v0.1.3 .
docker tag argus:v0.1.3 <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/argus:v0.1.3
docker push <ACCOUNT_ID>.dkr.ecr.ap-northeast-2.amazonaws.com/argus:v0.1.3

# Update task-def.json with new image tag, register, then:
aws ecs update-service --cluster argus --service argus-sentinel \
  --task-definition argus-sentinel:<NEW_REVISION> \
  --force-new-deployment --region ap-northeast-2
```

---

## Configuration

Pass `--config sentinel.toml` to load settings. The TOML file uses a `[sentinel]` wrapper:

```toml
[sentinel]
enabled = true

[sentinel.prefilter]
suspicion_threshold = 0.7     # 0.0-1.0; lower = more alerts, higher RPC cost
min_value_eth       = 1.0     # ignore transfers below this ETH value
min_gas_used        = 500000  # ignore low-gas transactions
min_erc20_transfers = 20      # flag txs with many token transfers
gas_ratio_threshold = 0.98    # flag near-block-limit gas usage

[sentinel.analysis]
max_steps             = 500000   # max opcode steps per replay
min_alert_confidence  = 0.6      # 0.0-1.0
prefilter_alert_mode  = false    # true = emit alerts even when deep analysis fails

[sentinel.alert]
rate_limit_per_minute  = 10   # suppress bursts
dedup_window_blocks    = 5    # suppress duplicate alerts within N blocks
```

### Dual-RPC Mode (Recommended)

Use a free public node for block polling and route only expensive deep replay queries to a paid archive endpoint:

```bash
argus sentinel \
  --rpc "https://eth.llamarpc.com" \
  --archive-rpc "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY" \
  --config sentinel.toml
```

| RPC Endpoint | Used For | Cost |
|-------------|----------|------|
| `--rpc` (public node) | `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getTransactionReceipt` | Free |
| `--archive-rpc` (Alchemy) | `eth_getProof`, `eth_getStorageAt`, `eth_getCode` (deep replay) | ~0.005% of TXs |

If `--archive-rpc` is omitted, `--rpc` is used for everything (existing behavior).

**Free public RPC endpoints**: `https://eth.llamarpc.com`, `https://cloudflare-eth.com`, `https://rpc.ankr.com/eth`

### RPC Cost Tuning

| Setting | Effect on RPC Cost |
|---------|--------------------|
| `--archive-rpc` (dual mode) | Near-zero Alchemy usage — only flagged TXs hit archive |
| `--prefilter-only` | Zero archive cost — no replay at all |
| `suspicion_threshold = 0.7` | ~0.02 flags/block (recommended for mainnet) |
| `suspicion_threshold = 0.3` | ~7 flags/block (expensive, use for testing only) |
| `min_erc20_transfers = 20` | Filters out normal DEX swaps |
| `prefilter_alert_mode = false` | Only emit alerts when deep analysis succeeds |

**Alchemy free tier**: 300M compute units/month. With dual-RPC mode and `suspicion_threshold=0.7`, Alchemy usage is negligible.

---

## Monitoring

### Prometheus scrape

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: argus
    static_configs:
      - targets: ["<HOST>:9090"]
```

Key counters at `http://<HOST>:9090/metrics`:

| Metric | Description |
|--------|-------------|
| `sentinel_blocks_scanned` | Total blocks processed |
| `sentinel_txs_scanned` | Total transactions seen by pre-filter |
| `sentinel_txs_flagged` | Transactions flagged as suspicious |
| `sentinel_alerts_emitted` | Alerts emitted |
| `sentinel_alerts_deduplicated` | Alerts suppressed by dedup |
| `sentinel_alerts_rate_limited` | Alerts suppressed by rate limiter |
| `sentinel_prefilter_total_us` | Cumulative pre-filter time (us) |
| `sentinel_deep_analysis_total_ms` | Cumulative deep analysis time (ms) |

### Health check

```bash
curl -s http://<HOST>:9090/health | jq .
# {
#   "status": "running",
#   "blocks_scanned": 12345,
#   "txs_scanned": 678901,
#   "alerts_emitted": 5,
#   "uptime_secs": 86400
# }
```

---

## Alert Output

Alerts are written to the `--alert-file` path as newline-delimited JSON:

```json
{
  "block_number": 22012345,
  "block_hash": "0xabc...",
  "tx_hash": "0xdef...",
  "tx_index": 42,
  "alert_priority": "High",
  "suspicion_score": 0.85,
  "suspicion_reasons": [
    { "FlashLoanSignature": { "provider_address": "0x..." } },
    { "MultipleErc20Transfers": { "count": 25 } }
  ],
  "summary": "Pre-filter alert (RPC): flash-loan, erc20-transfers (score=0.85)",
  "total_steps": 0,
  "detected_patterns": [],
  "fund_flows": [],
  "total_value_at_risk": "0x0"
}
```

### Analyzing Detected Alerts

Run Autopsy on any alert's TX hash for a full forensic report:

```bash
argus autopsy --tx 0xdef... --rpc https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
```

---

## 14-Day Validation Checklist

### Day 0 — Setup

- [ ] RPC endpoint confirmed (`curl -X POST -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' $RPC_URL`)
- [ ] Health endpoint responds `"status": "running"`
- [ ] Alert file or webhook configured
- [ ] Prometheus scraping (optional)

### Days 1-3 — Baseline

- [ ] `sentinel_blocks_scanned` incrementing (~5 blocks/min on mainnet)
- [ ] No error-rate spikes in logs
- [ ] Flag rate reasonable (< 1% of txs with threshold 0.7)

### Days 4-7 — Stability

- [ ] No RPC rate-limit errors (see Troubleshooting)
- [ ] Alert deduplication working (`sentinel_alerts_deduplicated`)
- [ ] Snapshot metrics: record `sentinel_txs_scanned` and `sentinel_txs_flagged`

### Days 8-12 — Performance

- [ ] Avg pre-filter latency: `sentinel_prefilter_total_us / sentinel_txs_scanned` < 50us
- [ ] Avg deep analysis: `sentinel_deep_analysis_total_ms / sentinel_alerts_emitted`
- [ ] Review alerts for quality (are flagged TXs genuinely suspicious?)

### Days 13-14 — Results

- [ ] Final snapshot of all metrics
- [ ] Flag rate: `sentinel_txs_flagged / sentinel_txs_scanned`
- [ ] Confirmation rate: `sentinel_alerts_emitted / sentinel_txs_flagged`
- [ ] Archive alert JSONL for offline review

---

## Troubleshooting

### RPC rate limit errors

Symptoms: logs show `429 Too Many Requests` or `rate limit exceeded`.

```bash
# Increase poll interval
argus sentinel --rpc "..." --poll-interval 5

# Or raise suspicion_threshold to reduce flagged TXs
# Or use --prefilter-only mode
# Or upgrade RPC plan (Alchemy free tier: 300M CU/month)
```

### Connection drops / timeouts

Argus retries transient RPC errors automatically. If drops are frequent:

1. Check RPC endpoint uptime
2. Try a backup RPC endpoint
3. Reduce `--poll-interval` to avoid long-idle connection resets

### No alerts after 24h

On mainnet with `suspicion_threshold=0.7`:

- `sentinel_txs_flagged` should be non-zero (pre-filter is working)
- Low alert count is normal — most mainnet transactions are benign
- Lower `suspicion_threshold` to 0.5 to see more flags

### CloudWatch Logs permission denied (ECS)

If ECS task fails with `CreateLogGroup` error:

```bash
# Create the log group manually
aws logs create-log-group --log-group-name /ecs/argus-sentinel --region ap-northeast-2

# Ensure IAM role has logs:CreateLogStream and logs:PutLogEvents permissions
```

### Binary not found (Docker)

```bash
# Verify the argus binary exists in the image
docker run --rm --entrypoint which tokamak/argus-demo:latest argus

# Run sentinel --help to check CLI is working
docker run --rm tokamak/argus-demo:latest "argus sentinel --help"
```
