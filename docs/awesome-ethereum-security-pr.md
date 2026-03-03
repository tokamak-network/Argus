# awesome-ethereum-security PR Draft

## PR Title

Add Argus — real-time attack detection and post-hack forensics toolkit

## PR Body

```markdown
## What is Argus?

[Argus](https://github.com/tokamak-network/Argus) is an open-source runtime security toolkit for Ethereum that detects attacks as they happen (real-time) and analyzes them after they've occurred (forensics).

Unlike static analysis tools (Slither, Mythril) that analyze contracts before deployment, Argus protects **after deployment** — monitoring live EVM execution at the opcode level.

### Key features:
- **Sentinel**: 2-stage detection pipeline (pre-filter at ~10-50μs/tx + deep opcode-level replay)
- **Autopsy Lab**: Post-hack forensic analysis with attack classification and fund flow tracing
- **Time-Travel Debugger**: GDB-style interactive replay at opcode granularity

### Case studies:
- [Balancer V2 $128M exploit analysis](https://github.com/tokamak-network/Argus/blob/main/docs/analysis-balancer-v2-exploit.md)
- [Bybit $1.5B supply chain attack analysis](https://github.com/tokamak-network/Argus/blob/main/docs/analysis-bybit-1.4b-exploit.md)

Built in Rust, fully open-source (MIT/Apache 2.0), self-hosted.
```

## Changes to README.md

### Option A: Add under "Bug finding tools"

Add this line after the Slither entry:

```markdown
* [Argus](https://github.com/tokamak-network/Argus) - Real-time Ethereum attack detection and post-hack forensics toolkit. Monitors live EVM execution at the opcode level with a 2-stage detection pipeline, attack pattern classification, and fund flow tracing.
```

### Option B: Add a new "Runtime Monitoring" section (preferred)

Add after "Bug finding tools" section:

```markdown
### Runtime monitoring

* [Argus](https://github.com/tokamak-network/Argus) - Real-time Ethereum attack detection and post-hack forensics toolkit. Monitors live EVM execution at the opcode level with a 2-stage detection pipeline, attack pattern classification, and fund flow tracing.
```

And add to the table of contents:

```markdown
  * [Runtime monitoring](#runtime-monitoring)
```

(after the `[Bug finding tools]` entry)

## How to Submit

```bash
# 1. Fork the repo
gh repo fork crytic/awesome-ethereum-security --clone

# 2. Create branch
cd awesome-ethereum-security
git checkout -b add-argus

# 3. Edit README.md (add the entry)
# ... apply changes from Option A or B above ...

# 4. Commit and push
git add README.md
git commit -m "Add Argus — real-time attack detection and forensics toolkit"
git push -u origin add-argus

# 5. Create PR
gh pr create \
  --repo crytic/awesome-ethereum-security \
  --title "Add Argus — real-time attack detection and post-hack forensics toolkit" \
  --body "$(cat <<'EOF'
## What is Argus?

[Argus](https://github.com/tokamak-network/Argus) is an open-source runtime security toolkit for Ethereum that detects attacks as they happen and analyzes them after they've occurred.

Unlike static analysis tools (Slither, Mythril) that analyze contracts before deployment, Argus protects **after deployment** — monitoring live EVM execution at the opcode level.

### Key features:
- **Sentinel**: 2-stage detection pipeline (pre-filter at ~10-50μs/tx + deep opcode-level replay)
- **Autopsy Lab**: Post-hack forensic analysis with attack classification and fund flow tracing
- **Time-Travel Debugger**: GDB-style interactive replay at opcode granularity
- **Case studies**: Balancer V2 $128M exploit, Bybit $1.5B supply chain attack

Built in Rust. Fully open-source (MIT/Apache 2.0). Self-hosted.

**Repo**: https://github.com/tokamak-network/Argus
EOF
)"
```
