# Argus AI Agent — Phase 0 PoC Report

**Date:** 2026-03-05
**Team:** kkirikkiri-dev-0305
**Verdict:** PASS — Phase 1 MVP 착수 승인

## Executive Summary

LLM이 EVM opcode trace를 분석하여 공격을 탐지할 수 있는지 검증하는 Phase 0 PoC를 완료했다.
13개 fixture (공격 3 + 정상 10)에 대해 **100% 정확도**를 달성하여, PRD 기준 80%를 크게 초과했다.
월 운영 비용은 캐시 적용 시 **$67-250** 범위로 $150 예산 내 운영이 가능하다.

## Test Results

### Accuracy: 13/13 (100.0%)

| Fixture | Expected | Got | Confidence | Type | Cost |
|---------|----------|-----|------------|------|------|
| attack_flash_loan_euler | attack | attack | 0.85-0.95 | FlashLoan | $0.017 |
| attack_price_manipulation_balancer | attack | attack | 0.80-0.85 | PriceManipulation | $0.012 |
| attack_reentrancy_dao | attack | attack | 0.90-0.95 | Reentrancy | $0.015 |
| normal_contract_deploy_factory | benign | benign | 0.95 | - | $0.019 |
| normal_contract_deploy_simple | benign | benign | 1.00 | - | $0.012 |
| normal_defi_liquidity_add | benign | benign | 0.95 | - | $0.019 |
| normal_defi_swap_multi_hop | benign | benign | 0.95 | - | $0.022 |
| normal_defi_swap_uniswap | benign | benign | 0.95 | - | $0.022 |
| normal_eth_transfer_contract | benign | benign | 1.00 | - | $0.010 |
| normal_eth_transfer_large | benign | benign | 1.00 | - | $0.009 |
| normal_eth_transfer_simple | benign | benign | 1.00 | - | $0.008 |
| normal_multi_call_batch | benign | benign | 0.90 | - | $0.021 |
| normal_multi_call_governance | benign | benign | 0.95 | - | $0.018 |

### Key Observations

1. **Attack detection**: 3/3 공격 패턴 모두 정탐. AttackType 분류도 정확.
2. **False positive rate**: 0%. 정상 TX 10개 모두 정확히 benign으로 분류.
3. **Confidence calibration**: 공격은 0.80-0.95, 정상은 0.90-1.00. 적절한 분리.
4. **가장 어려운 케이스**: `normal_multi_call_batch` (confidence 0.90) — 2개 revert 포함하여 공격과 유사하나 정확히 판별.

## Cost Analysis

### 2-Tier Model Comparison

| Metric | gemini-3-flash | gemini-3-pro |
|--------|---------------|-------------|
| Role | Screening (fast) | Deep analysis |
| Accuracy | 13/13 (100%) | 13/13 (100%) |
| Total cost (13 req) | $0.206 | $0.113 |
| Avg cost/req | $0.016 | $0.009 |
| Avg cost/req (cached) | $0.0007 | TBD |
| Input tokens (total) | 32,428 | 32,428 |
| Output tokens (total) | 7,262 | 7,283 |

Note: gemini-3-pro is cheaper per request than flash — likely LiteLLM proxy pricing.

### Monthly projection (30,000 req/month, gemini-3-flash)

| Cache hit rate | Monthly cost | Budget status |
|----------------|-------------|---------------|
| 90% | $66.9 | Within $150 |
| 75% | $130.5 | Within $150 |
| 50% | $250.5 | Over $150 |
| 0% | $480.0 | Over $150 |

**Conclusion:** Cache hit rate 75% 이상이면 $150 예산 내 운영 가능. 시스템 프롬프트 캐싱 (입력의 ~60%)이 자동 적용되므로 실제 운영에서 75%+ 달성 예상. gemini-3-pro 단독 사용 시에도 $0.009/req로 더 저렴.

## Architecture

```
AgentContext (fixture JSON)
       │
       ▼
LiteLLMClient::judge(model)
       │
       ├─ System prompt (SYSTEM_PROMPT constant)
       ├─ User message (AgentContext JSON)
       └─ tool_choice: forced ("analyze_evm_trace")
       │
       ▼
LiteLLM Proxy (api.ai.tokamak.network)
       │
       ├─ Screening:    gemini-3-flash (fast, $0.016/req)
       └─ Deep analysis: gemini-3-pro  (strong, $0.009/req)
       │
       ▼
parse_verdict() → AgentVerdict
```

### Key files

| File | Lines | Purpose |
|------|-------|---------|
| `src/sentinel/ai/types.rs` | ~395 | AgentContext, AgentVerdict, AttackType, CostTracker |
| `src/sentinel/ai/client.rs` | ~887 | AiClient trait + LiteLLMClient + AnthropicClient |
| `src/sentinel/ai/prompts.rs` | ~80 | SYSTEM_PROMPT (5 attack patterns) |
| `src/sentinel/ai/fixtures.rs` | ~310 | Fixture loader utilities |
| `src/sentinel/ai/poc_test.rs` | ~212 | PoC integration tests (6 tests) |
| `tests/fixtures/ai/` | 13 files | Attack + normal fixture JSONs |

### Feature flag

```toml
# Cargo.toml
ai_agent = ["sentinel", "dep:reqwest", "dep:serde_json"]
```

```rust
// src/sentinel/mod.rs
#[cfg(feature = "ai_agent")]
pub mod ai;
```

## Decisions Made

| ID | Decision | Rationale |
|----|----------|-----------|
| D1 | AgentContext JSON as LLM input format | Structured JSON with call_graph, storage_mutations, transfers — not raw opcode trace |
| D2 | input_selector=None, old_value=zero | Phase 0 PoC에서 충분 |
| D3 | reqwest direct (superseded by D4) | anthropic-sdk-rust lacks prompt caching |
| D4 | LiteLLM proxy switch | Model flexibility, unified API format |
| D5 | Gemini 2-tier: flash (screening) + pro (deep) | Claude not available on proxy, both gemini models achieved 100% |

## Limitations and Risks

1. **Synthetic fixtures**: 모든 fixture가 수동 생성. 실제 mainnet TX로 추가 검증 필요.
2. **Small sample size**: 13개 fixture는 통계적으로 유의미하지 않음. Phase 1에서 100+ TX 필요.
3. **No adversarial testing**: 공격을 정상으로 위장하는 케이스 미포함.
4. **Single model**: gemini-3-flash만 테스트. 다른 모델 (gpt-5.2, deepseek) 비교 필요.
5. **No latency under load**: Sequential 호출만 테스트. 동시 요청 시 성능 미검증.

## Recommendations for Phase 1

1. **Mainnet TX 검증**: 14일 운영 데이터에서 실제 suspicious TX로 AI 분석 실행
2. **Hallucination Guard 구현**: evidence_valid 필드 실제 검증 로직 (`guard.rs`)
3. **Context Extractor 구현**: StepRecord → AgentContext 자동 변환 (`context.rs`)
4. **2-tier pipeline**: gemini-3-flash (screening) → gemini-3-pro (deep analysis)
5. **비용 모니터링**: CostTracker 영속화 + circuit breaker 활성화

## How to Reproduce

```bash
# 1. Set environment variables
export LITELLM_API_KEY=<your-key>
export LITELLM_BASE_URL=https://api.ai.tokamak.network

# 2. Run PoC tests
cargo test --features ai_agent poc_test -- --ignored --nocapture

# 3. Run all tests (non-API)
cargo test --features ai_agent
```

## Test Summary

| Category | Count | Status |
|----------|-------|--------|
| Existing tests | 436 | PASS |
| AI type tests | 29 | PASS |
| Fixture loader tests | 11 | PASS |
| Client unit tests | 9 | PASS |
| Prompt tests | 3 | PASS |
| PoC integration tests | 6 | PASS (--ignored) |
| **Total** | **461 + 6** | **All PASS** |
