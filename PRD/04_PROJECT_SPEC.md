# Argus AI Agent — Project Spec

> **문체:** 이 문서는 명령체("~하라")를 사용한다. 개발 규칙 문서이기 때문이다.

## Glossary (용어집)

업계 표준 영어 용어는 원문을 유지한다. Argus 자체 개념은 한글로 기술한다.

| 용어 | 의미 |
|------|------|
| AgentContext | AI에게 전달되는 TX 분석 컨텍스트 (구조화된 JSON) |
| AgentVerdict | AI의 판단 결과 |
| CostTracker | 비용 추적/제한 엔티티 |
| Hallucination Guard | AI evidence가 실제 데이터에 존재하는지 검증하는 후처리 레이어 |
| Circuit breaker | 연속 실패 시 자동으로 기능을 비활성화하는 안전 장치 |
| Prompt caching | 반복되는 시스템 프롬프트를 캐싱하여 비용 90% 절감하는 Anthropic 기능 |
| 2-pass 알림 | 규칙 기반 결과를 즉시 발행 → AI 결과로 보강/취소하는 비동기 구조 |

## Tech Stack

| 구분 | 선택 | 이유 |
|------|------|------|
| AI SDK | `anthropic-sdk-rust` (crates.io) 또는 LiteLLM 프록시 | 아래 비교표 참조. 커뮤니티 crate이므로 관리 중단 리스크 있음 — [01_PRD.md § Risks](./01_PRD.md#6-risks--mitigations) 참조 |
| 모델 (스크리닝) | Claude Haiku 4.5 | ~$0.005/req (prompt caching 적용 시), 빠른 응답. 공식 단가: input $1/MTok, output $5/MTok |
| 모델 (심층) | Claude Sonnet 4.6 | ~$0.02/req, 높은 정확도 |
| API 키 관리 | 환경변수 (`ANTHROPIC_API_KEY`). LiteLLM 시 TOML에 `litellm_api_base` (프록시 URL) + `litellm_api_key_env` (키 환경변수명) 설정 | 시크릿 노출 방지 |
| 직렬화 | serde_json | AgentContext/AgentVerdict JSON 변환 |
| 비용 영속성 | 파일 기반 (JSON) | 외부 DB 의존성 없음 |
| Feature flag | `ai_agent` | 기존 빌드 격리 |

### AI SDK 선택지: anthropic-sdk-rust vs LiteLLM

| 항목 | anthropic-sdk-rust | LiteLLM 프록시 |
|------|-------------------|---------------|
| 통합 방식 | Rust crate 직접 의존 | HTTP 프록시 서버 (OpenAI-compatible API) |
| 모델 교체 | Anthropic 전용 | 100+ 프로바이더 (OpenAI, Gemini, Mistral, Ollama 등) |
| 추가 인프라 | 없음 | LiteLLM 프록시 서버 운영 필요 (Python) |
| Rust 호환 | 네이티브 | reqwest로 OpenAI API 호출 (간단) |
| 비용 추적 | 자체 CostTracker 구현 | LiteLLM 내장 비용 추적 + 예산 관리 |
| 로드밸런싱 | 없음 (단일 프로바이더) | 프로바이더 간 자동 폴백/로드밸런싱 |
| 레이턴시 | 직접 호출 (최소) | 프록시 경유 (Python 처리 포함 수십ms 추가) |
| 운영 복잡도 | 낮음 (crate만 추가) | 중간 (Python 프록시 서버 별도 운영) |

### 추천 전략

**MVP: `anthropic-sdk-rust`로 시작** — 추가 인프라 없이 빠르게 검증.

**Phase 2+: LiteLLM 전환 고려** — 다음 시점에 전환 검토:
- 다른 모델(GPT-4o, Gemini)과 A/B 테스트가 필요할 때
- 프로바이더 장애 시 자동 폴백이 필요할 때
- 셀프호스팅 모델(Ollama)로 비용 절감을 시도할 때

**전환 비용 최소화 설계**: `client.rs`를 trait 기반으로 설계하여 `AnthropicClient`와 `LiteLLMClient`를 교체 가능하게 구현.

```rust
#[async_trait]
trait AiClient: Send + Sync {
    async fn judge(&self, context: &AgentContext) -> Result<AgentVerdict, AiError>;
}

struct AnthropicClient { /* anthropic-sdk-rust 직접 호출 */ }
struct LiteLLMClient { /* OpenAI-compatible HTTP 호출 */ }
```

## Project Structure

```
src/sentinel/ai/
├── mod.rs          # Module exports + feature gate
├── types.rs        # AgentContext, AgentVerdict, CostTracker, AttackType enum
├── context.rs      # ContextExtractor (trace → AgentContext)
├── judge.rs        # AiJudge (2-tier Haiku/Sonnet pipeline)
├── guard.rs        # Hallucination Guard (evidence 검증)
├── client.rs       # AiClient trait + AnthropicClient / LiteLLMClient
├── cost.rs         # CostTracker + circuit breaker
└── prompts.rs      # System/user prompt templates
```

## Feature Flag

```toml
# Cargo.toml
[features]
default = ["sentinel", "autopsy"]
sentinel = ["axum", "tokio", ...]
autopsy = ["reqwest", "sha3", ...]
ai_agent = ["anthropic-sdk-rust", "sentinel"]
cli = ["clap", "rustyline"]
```

> Cargo에서 하이픈(`-`)은 언더스코어(`_`)로 자동 변환되므로 `ai_agent`로 통일한다.

## Configuration (TOML)

```toml
[ai]
enabled = true
backend = "anthropic"               # "anthropic" | "litellm"

# Anthropic 직접 호출 설정
anthropic_api_key_env = "ANTHROPIC_API_KEY"

# LiteLLM 프록시 설정 (backend = "litellm" 일 때)
# litellm_api_base = "http://localhost:4000"  # LiteLLM 프록시 서버 URL (API 키가 아님)
# litellm_api_key_env = "LITELLM_API_KEY"     # LiteLLM 프록시 인증 키 (선택)

screening_model = "claude-haiku-4-5-20251001"
deep_model = "claude-sonnet-4-6"

# 공격 의심도가 이 값 이상이면 Sonnet으로 에스컬레이션.
# 높을수록: Sonnet 요청 감소 (비용 절감, 정밀도 하락)
# 낮을수록: Sonnet 요청 증가 (비용 증가, 정밀도 향상)
is_suspicious_confidence_threshold = 0.6

monthly_budget_usd = 150.0          # 산출 근거: 01_PRD.md § 비용 추정 근거
daily_limit_usd = 10.0
hourly_rate_limit = 100              # 시간당 최대 요청 수
max_concurrent_per_block = 3         # 블록당 최대 동시 AI 요청
request_timeout_secs = 30
max_retries = 3
max_context_tokens = 4000            # 컨텍스트 크기 제한

# Circuit breaker
circuit_breaker_threshold = 5        # 연속 실패 횟수
circuit_breaker_cooldown_secs = 600  # 비활성화 기간 (10분)
```

## DO NOT Rules

1. **DO NOT** mutate existing struct fields — 새 필드 추가 시 `Option<T>`으로 하위 호환 유지
2. **DO NOT** 기존 테스트 깨뜨리기 — `ai_agent` feature 없이 `cargo test` 통과 필수
3. **DO NOT** API 키를 코드에 하드코딩 — 환경변수만 사용
4. **DO NOT** AI 응답을 파싱 없이 신뢰 — JSON schema 검증 + Hallucination Guard 필수
5. **DO NOT** 비용 제한 없이 API 호출 — CostTracker 체크 선행
6. **DO NOT** 동기 API 호출 — 모든 AI 호출은 async
7. **DO NOT** CostTracker 확인 없이 Sonnet을 직접 호출 — Haiku 스크리닝 필수
8. **DO NOT** AI 장애 시 전체 파이프라인 중단 — circuit breaker + 규칙 기반 폴백
9. **DO NOT** 800줄 이상의 파일 생성 — 모듈 분리
10. **DO NOT** `#[cfg(feature = "ai_agent")]` 없이 AI 코드 노출

## ALWAYS DO Rules

1. **ALWAYS** `#[cfg(feature = "ai_agent")]`로 AI 코드 게이트
2. **ALWAYS** CostTracker 잔액 확인 후 API 호출
3. **ALWAYS** API 응답에 타임아웃 설정 (default 30초)
4. **ALWAYS** AgentVerdict를 JSON으로 파싱하고 schema 검증
5. **ALWAYS** 토큰 사용량과 비용을 CostTracker에 기록
6. **ALWAYS** API 실패 시 exponential backoff 재시도 (최대 3회)
7. **ALWAYS** fixture TX 20개+로 회귀 테스트 유지 (공격 10 + 정상 10)
8. **ALWAYS** 프롬프트 변경 시 기존 fixture 테스트 재실행
9. **ALWAYS** Haiku 스크리닝을 거친 후 Sonnet 에스컬레이션
10. **ALWAYS** Hallucination Guard로 AI evidence를 AgentContext 데이터와 대조 검증

## Test Strategy

```bash
# AI 코드 포함 빌드
cargo check --features ai_agent

# AI 테스트 (ANTHROPIC_API_KEY 필요)
cargo test --features ai_agent -- ai

# 기존 테스트 영향 없음 확인
cargo test

# Clippy
cargo clippy --features ai_agent -- -D warnings
```

### 테스트 분류

| 유형 | 대상 | API 필요 |
|------|------|----------|
| Unit | types.rs, cost.rs, context.rs, guard.rs | No |
| Integration | judge.rs (mock response) | No |
| E2E | 전체 파이프라인 | Yes (ignored by default) |
| Fixture | 공격 TX 10개 + 정상 TX 10개 판단 | Yes (ignored by default) |

## Deployment

```bash
# 환경변수 설정 (.env 파일 또는 Secrets Manager 사용 권장)
# .env 파일에 ANTHROPIC_API_KEY=sk-ant-xxx... 설정 후:
set -a; source .env; set +a    # set -a로 export를 자동 적용

# AI 모드로 Sentinel 실행
cargo run --bin argus --features "cli,ai_agent" -- sentinel \
  --rpc https://eth-mainnet.g.alchemy.com/v2/KEY \
  --config sentinel.toml

# AI 모드로 Autopsy 실행
cargo run --bin argus --features "cli,ai_agent" -- autopsy \
  --tx 0x... --rpc https://... --ai

# 실행 후 메트릭 확인
curl http://localhost:9090/metrics | grep argus_ai_requests_total

# Docker (AI 포함) — .env 파일로 시크릿 전달
docker build --build-arg FEATURES="sentinel,autopsy,ai_agent" -t argus-ai .
docker run --env-file .env argus-ai
```
