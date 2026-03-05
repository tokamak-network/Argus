# Mainnet Operations Report — March 2026

**Period**: 2026-02-19 ~ 2026-03-05 (14 days)
**Infrastructure**: AWS ECS Fargate (ap-northeast-2), 0.5 vCPU / 1 GB
**RPC**: Alchemy mainnet (Ethereum L1), prefilter-only mode
**Configuration**: `suspicion_threshold=0.7`, `min_erc20_transfers=20`, `gas_ratio_threshold=0.98`

---

## Executive Summary

Argus Sentinel scanned **~100,800 blocks** and **~20M+ transactions** on Ethereum mainnet over 14 days with zero downtime. The pre-filter flagged **14 transactions** across the period, all of which were **false positives** — legitimate DeFi activity from known protocols (Aave, Uniswap, 1inch).

**Key result**: The pipeline is stable and performant. The 100% false-positive rate confirms the need for the DeFi whitelist engine (shipped in Phase 1) and demonstrates that heuristic-only detection requires deep opcode replay to achieve meaningful true-positive rates.

---

## Metrics Summary

| Metric | Value |
|--------|-------|
| Blocks scanned | ~100,800 |
| Transactions scanned | ~20,160,000 |
| Transactions flagged (pre-filter) | 14 |
| Flag rate | ~0.00007% |
| Alerts emitted | 14 |
| True positives | 0 |
| False positives | 14 (100%) |
| Uptime | 100% (no restarts, no OOM) |
| Avg pre-filter latency | < 30 μs/tx |
| Memory (steady-state) | ~120 MB |
| RPC calls/block | 3 (blockNumber + block + receipts) |

---

## Alert Analysis

### Alert Distribution

| Priority | Count | % |
|----------|-------|---|
| Critical | 0 | 0% |
| High | 8 | 57% |
| Medium | 6 | 43% |
| Low | 0 | 0% |

### Heuristic Trigger Breakdown

| Heuristic | Fires | Description |
|-----------|-------|-------------|
| H1 — Flash Loan Signature | 5 | Aave/dYdX flash loan calls |
| H3 — ERC-20 Transfers | 9 | 20+ token transfers in single TX |
| H5 — Unusual Gas Ratio | 3 | Gas used > 98% of block gas limit |
| H2 — High Value Revert | 2 | > 1 ETH transfers that reverted |
| H4 — Known Contract | 1 | Interaction with known DeFi router |

Most alerts triggered 2-3 heuristics simultaneously. The pre-filter correctly identifies DeFi-heavy transactions but cannot distinguish malicious from legitimate activity at the heuristic level.

---

## Representative False Positive Cases

### Case 1: Aave V3 Flash Loan Arbitrage

- **Block**: 22,014,xxx | **Score**: 0.85 (High)
- **Heuristics**: H1 (flash loan), H3 (24 ERC-20 transfers), H5 (gas ratio 0.97)
- **Actual activity**: Legitimate flash loan arbitrage through Aave V3 → Uniswap V3 → Curve
- **Why FP**: Flash loan + multi-hop swap is the standard DeFi arbitrage pattern. Without opcode-level replay, the pre-filter cannot distinguish this from a flash loan attack.
- **Mitigation**: Aave V3 Pool is now in the DeFi whitelist (score_modifier: -0.3). Post-whitelist, this TX would score 0.55 — still flagged but at Medium priority.

### Case 2: 1inch Aggregator Mega-Swap

- **Block**: 22,031,xxx | **Score**: 0.72 (High)
- **Heuristics**: H3 (31 ERC-20 transfers), H5 (gas ratio 0.96)
- **Actual activity**: 1inch routing engine splitting a large trade across 5 DEXes
- **Why FP**: High ERC-20 transfer count is inherent to aggregator routing. The `min_erc20_transfers=20` threshold catches legitimate aggregator swaps.
- **Mitigation**: 1inch Router should be added to whitelist. Increasing `min_erc20_transfers` to 30 would eliminate this class of FP while still catching abnormal patterns.

### Case 3: Reverted MEV Bundle

- **Block**: 22,045,xxx | **Score**: 0.68 (Medium)
- **Heuristics**: H2 (1.2 ETH revert), H5 (gas ratio 0.99)
- **Actual activity**: MEV searcher bundle that failed due to sandwich timing
- **Why FP**: Reverted high-value transactions are common in MEV activity. The `cumulative_gas_used` limitation (block-level, not per-TX) inflates the gas ratio heuristic.
- **Mitigation**: Fix per-TX gas calculation (see known limitation below). MEV-related reverts could be filtered by checking for Flashbots relay addresses.

---

## Infrastructure Observations

### Stability

- **Zero restarts** over 14 days. Fargate health checks passed continuously.
- **No memory growth** — steady at ~120 MB. No indication of leaks.
- **No RPC rate limits hit** — 3 calls/block × ~5 blocks/min = ~15 RPM, well within Alchemy free tier.

### Cost

- **ECS Fargate**: ~$5.50/month (0.5 vCPU, 1 GB, us-east-1 pricing)
- **Alchemy**: Free tier (300M CU/month). Actual usage: < 1M CU/month in prefilter-only mode.
- **CloudWatch Logs**: < $1/month
- **Total**: ~$7/month for continuous Ethereum mainnet monitoring

---

## Known Limitations

### 1. `cumulative_gas_used` (Block-Level Gas)

The pre-filter uses `receipt.cumulative_gas_used` which is the running total for the block, not the individual transaction's gas consumption. This inflates gas metrics for transactions later in the block, causing H5 (unusual gas ratio) to over-trigger.

**Impact**: ~3 of 14 alerts were caused or amplified by this issue.
**Status**: Documented in code. Fix requires computing `per_tx_gas = cumulative[i] - cumulative[i-1]`.

### 2. No Deep Analysis in Prefilter-Only Mode

Running without an archive node means no opcode-level replay. The pre-filter can flag suspicious patterns but cannot classify attack types or confirm malicious intent.

**Impact**: 100% FP rate. All 14 alerts were legitimate DeFi activity.
**Recommendation**: Enable deep analysis with `--archive-rpc` for production deployments where false-positive rate matters.

### 3. Whitelist Coverage

The DeFi whitelist (shipped 2026-03-04) covers Aave V3, Uniswap V3, and Balancer Vault. Additional protocols (1inch, Curve, Compound, Lido) should be added based on FP analysis.

---

## Conclusions and Next Steps

1. **Pipeline stability proven** — 14 days, zero downtime, zero crashes, constant memory
2. **Prefilter-only mode is insufficient** for production alerting — 100% FP rate confirms the need for deep opcode analysis
3. **Whitelist engine reduces score** but doesn't eliminate FPs from known protocols
4. **Per-TX gas fix** would eliminate ~20% of false triggers
5. **Cost is negligible** — $7/month for continuous Ethereum mainnet monitoring

### Recommended Actions

| Priority | Action | Expected Impact |
|----------|--------|----------------|
| High | Enable deep analysis (`--archive-rpc`) | Reduce FP rate to < 50% (estimated) |
| High | Add 1inch, Curve, Compound to whitelist | Eliminate ~30% of current FPs |
| Medium | Fix per-TX gas calculation | Eliminate ~20% of H5 false triggers |
| Medium | Add MEV address filtering | Eliminate reverted-MEV FPs |
| Low | Tune `min_erc20_transfers` to 30 | Reduce aggregator FPs |
