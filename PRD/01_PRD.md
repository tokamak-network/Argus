# Argus AI Agent Integration — Product Requirements Document

> **독자:** Argus 핵심 개발자 (Rust + EVM 배경 필요)

## 1. Product Overview

Argus의 기존 규칙 기반 탐지 파이프라인에 AI 에이전트(LLM)를 통합하여, 알려지지 않은 공격 패턴까지 탐지하고 오탐을 줄이며 사람이 읽을 수 있는 판단 근거를 제공한다.

### 왜 필요한가?

> 경쟁 현황: Forta는 ML 기반 봇 네트워크, Hexagate는 사전 TX 시뮬레이션 + ML을 사용한다. 그러나 LLM 기반 opcode-level 추론을 통합한 오픈소스 탐지 도구는 아직 없다. 상세 분석은 [`docs/competitive-analysis.md`](../docs/competitive-analysis.md) 참조.

현재 Argus의 탐지 알고리즘은 다음 한계를 가진다:

| 문제 | 현재 상태 | AI 에이전트 해결 |
|------|----------|----------------|
| 알려진 패턴만 탐지 | 4개 분류기 (reentrancy, flash loan, price manipulation, access control) | 구조화된 trace 기반 추론으로 미분류 공격 탐지 |
| 높은 오탐률 | 13개 하드코딩 주소, 고정 점수 | 컨텍스트 기반 판단으로 오탐 감소 |
| 판단 근거 부재 | 점수만 반환 | 자연어 reasoning + evidence 제공 |
| ML 모델 미완성 | 하드코딩된 mean/stddev placeholder | LLM이 ML 모델을 **보완** (ML은 빠른 1차 필터로 유지) |

### 핵심 원칙

1. **기존 파이프라인 보존** — AI는 추가 레이어, 기존 규칙 기반 + ML 탐지를 대체하지 않음
2. **비용 통제** — 월 $150 목표 (Phase 1 게이트: $200 미만). Haiku/Sonnet 2-tier + prompt caching
3. **Feature flag 격리** — `ai_agent` feature flag로 기존 빌드에 영향 없음
4. **Graceful degradation** — API 장애 시 규칙 기반으로 자동 폴백 (circuit breaker)
5. **프로바이더 교체 가능** — trait 기반 설계로 Anthropic 직접 호출 / LiteLLM 프록시 전환 가능
6. **2-pass 알림** — 규칙 기반 결과를 즉시 발행하고, AI 결과로 보강/취소하는 비동기 구조

## 2. User Scenarios

### Scenario 1: 실시간 탐지 강화
Sentinel이 pre-filter에서 의심 TX를 잡으면, 규칙 기반 알림을 즉시 발행한다. 동시에 AI 에이전트가 비동기로 opcode trace를 분석하여 "이것이 공격인지, 왜 그런지"를 판단하고, 결과로 알림을 보강하거나 오탐으로 취소한다.

### Scenario 2: Autopsy AI 모드
사후 분석에서 `--ai` 플래그로 AI 판단을 추가. 포렌식 리포트에 AI의 공격 분류와 근거가 포함된다.

### Scenario 3: 비용 초과 자동 차단
월 예산 도달 시 AI 분석을 자동 중단하고 규칙 기반으로 폴백. 운영자에게 알림.

## 3. Features

| # | Feature | 복잡도* | MVP | 설명 |
|---|---------|---------|-----|------|
| F1 | AI 판단 엔진 | 복잡 | Yes | 빠르고 저렴한 AI(Haiku)가 1차 스크리닝 → 의심스러운 건만 정밀 AI(Sonnet)가 분석 |
| F2 | 컨텍스트 추출기 | 보통 | Yes | opcode trace → AgentContext JSON (~2-5KB) 변환 |
| F3 | Autopsy AI 모드 | 보통 | Yes | `--ai` 플래그로 포렌식에 AI 판단 추가 |
| F4 | 비용 가드레일 | 보통 | Yes | 월/일 예산, 토큰 추적, 자동 차단, 시간당 rate limit |
| F5 | Prompt 버전 관리 | 간단 | No | TOML 기반 프롬프트 버전 관리 |
| F6 | Tool-use 통합 | 복잡 | No | AI가 직접 etherscan/4byte 등 외부 도구 호출 |
| F7 | Sandwich 탐지 | 복잡 | No | 멀티-TX 컨텍스트 분석 (블록 내 TX 순서) |

> *복잡도 기준: **간단** = 1주 이내, 신규 외부 의존성 없음 / **보통** = 1-2주, 기존 패턴 확장 / **복잡** = 2주+, 신규 아키텍처 결정 또는 외부 API 통합 포함

## 4. User Flow

```
Pre-Filter (규칙 기반, ~10-50us)
    │
    ├─ 즉시: 규칙 기반 알림 발행 (기존 파이프라인)
    │
    ▼ suspicious TX (비동기)
Context Extractor
    │ opcode trace → AgentContext JSON
    ▼
CostTracker 예산 확인
    │
    ├─ 예산 소진 → SKIP (규칙 기반 결과만 유지)
    │
    ▼
Haiku Screening (~$0.005/req, prompt caching 적용 시)
    │
    ├─ is_suspicious_confidence < 0.6 → 규칙 기반 결과만 유지
    │
    ▼ is_suspicious_confidence >= 0.6 (공격 의심도 60% 이상이면 에스컬레이션)
Sonnet Deep Analysis (~$0.02/req)
    │
    ▼
AgentVerdict + Hallucination Guard (evidence 검증)
    │
    ├─ is_attack: true → 알림 보강 (AI reasoning 추가)
    └─ is_attack: false → 알림 취소 + false_positive_reason 기록
```

### 비용 추정 근거

| 항목 | 계산 |
|------|------|
| AgentContext 크기 | 2-5KB JSON ≈ 1,500-3,500 input tokens |
| 시스템 프롬프트 | ~1,000 tokens (prompt caching 대상 — 캐시 히트 시 input 단가 90% 절감) |
| Haiku input (캐시 미적용) | (1,000 + 1,500-3,500) × $1.00/MTok = $0.0025-0.0045 |
| Haiku input (캐시 적용) | 시스템 1,000 × $0.10/MTok + 유저 1,500-3,500 × $1.00/MTok = $0.0016-0.0036 |
| Haiku output | ~500 tokens × $5.00/MTok = $0.0025 |
| **Haiku 총 비용** | **~$0.004-0.006/req** (캐시 적용 시) |
| Sonnet input (캐시 적용) | 시스템 1,000 × $0.30/MTok + 유저 1,500-3,500 × $3.00/MTok = $0.0048-0.0108 |
| Sonnet output | ~800 tokens × $15.00/MTok = $0.012 |
| **Sonnet 총 비용** | **~$0.017-0.023/req** (캐시 적용 시) |
| 에스컬레이션 비율 | ~20% (PoC에서 측정 필요) |
| **월 $150 예산** | 에스컬레이션 20% 가정 시: 의심 TX 1건당 평균 $0.005 + 0.2 × $0.020 = **$0.009/TX**. $150 ÷ $0.009 ≈ **~16,600 TX/월 ≈ ~550 TX/일** |

> 하루 ~550 TX는 현재 의심 TX 발생량(하루 ~50-200건, 14일 운영 기준) 대비 2.5-10배 여유다. 대규모 공격 이벤트 시 급증 가능하며, 이때는 CostTracker의 hourly_rate_limit(100)과 블록당 동시 요청 제한(3)이 비용 폭발을 방지한다.

## 5. Success Criteria

| Metric | Target | 베이스라인 | 측정 방법 |
|--------|--------|-----------|----------|
| 월 비용 | < $150 | N/A | CostTracker 로그 |
| Haiku 응답 시간 | < 2초 | N/A | 메트릭 P95 |
| 오탐 감소율 | > 30% | Phase 0에서 현재 오탐률 측정 | 14일 운영 비교 (AI on/off) |
| AI 판단 정확도 | > 80% (단독) | N/A | Phase 0: 13개(공격 3+정상 10)로 PoC 검증. Phase 1: fixture 20개+(공격 10+정상 10*)로 회귀 테스트. AI는 보조 레이어이므로 규칙 기반(1차) + AI(2차) 결합 시 전체 정확도 95%+ 목표. |
| True Negative Rate | > 90% | N/A | 정상 TX fixture 기반 |
| 가용성 | 99%+ (AI 장애 시 폴백) | N/A | uptime 모니터링 |

> *정상 TX 구성: 단순 ETH 전송 3개, DeFi 스왑 3개, 다중 internal call TX 2개, 컨트랙트 배포 2개. 의심스러워 보이지만 정상인 TX를 반드시 포함하여 정확도 부풀림을 방지한다.

## 6. Risks & Mitigations

| 리스크 | 발생 확률 | 영향도 | 완화 전략 |
|--------|----------|--------|----------|
| **LLM Hallucination** — 그럴듯하지만 틀린 판단 | 높음 | 높음 | Hallucination Guard: AI의 evidence가 AgentContext에 실제 존재하는지 프로그래밍적 검증 |
| **비용 폭발** — 공격 시 의심 TX 급증 | 중간 | 높음 | CostTracker 시간당 rate limit + 블록당 최대 동시 AI 요청 3건 제한 |
| **API 레이턴시** — Haiku 2초 + Sonnet 5초 | 높음 | 중간 | 2-pass 비동기 구조 (규칙 기반 즉시 → AI 보강). 실시간성에 영향 없음 |
| **Anthropic API 장애** | 낮음 | 높음 | Circuit breaker: 연속 5회 실패 시 10분간 AI 비활성화. `auto_pause.rs` 패턴 재사용 |
| **Prompt Injection** — 악의적 trace 생성 | 낮음 | 중간 | AgentContext는 구조화된 JSON만 전달, raw calldata 미포함 |
| **PoC 실패** — LLM이 EVM trace를 이해 못함 | 중간 | 치명적 | Phase 0 검증 + 3단계 대안 시도 (아래 상세) |
| **분석 패턴 노출** — AI API로 전송되는 쿼리 패턴에서 탐지 전략 역추론 | 낮음 | 중간 | AgentContext는 구조화된 JSON만 전달 (원본 calldata 미포함). 시스템 프롬프트는 캐싱되어 반복 전송 안 됨. 장기적으로 self-hosted 모델 옵션 검토 |
| **SDK 단종** — `anthropic-sdk-rust` 커뮤니티 crate 관리 중단 | 중간 | 중간 | trait 기반 설계로 LiteLLM 전환 가능. 최악 시 reqwest로 직접 HTTP 호출 (Anthropic Messages API는 단순 REST) |

> **PoC 실패 시 대안 순서:**
> 1. 프롬프트 재설계 + 다른 컨텍스트 포맷 (call_graph 요약 방식 변경)
> 2. GPT-4o 등 다른 모델 테스트 (LiteLLM 설계가 이를 용이하게 함)
> 3. Fine-tuned 소형 모델 검토 (비용 절감 but 추가 2-4주)
> 4. 3개 대안 모두 실패 시 PRD 폐기

## 7. Out of Scope (MVP)

- 자체 모델 학습/파인튜닝
- 실시간 mempool AI 분석 (비용 폭발)
- 멀티체인 지원
- 사용자 대면 챗봇 UI
- Tool-use (Phase 3)
- Sandwich/MEV 탐지 (Phase 3)
