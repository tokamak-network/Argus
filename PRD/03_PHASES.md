# Argus AI Agent — Phase Plan

> 파일 구조 및 기술 상세는 [04_PROJECT_SPEC.md](./04_PROJECT_SPEC.md) 참조.

## Phase 0: PoC 검증 (1-2 weeks)

**목적:** LLM이 EVM opcode trace를 분석하여 공격을 탐지할 수 있는지 검증한다.
Phase 0이 실패하면 이후 모든 Phase는 중단하고 PRD를 재검토한다.

> **일정 근거:** 핵심 경로는 fixture 변환(2일) + API 테스트(2일) + 문서화(1일) = 1주. SDK 호환성 이슈 발생 시 대안 조사(reqwest 직접 호출)에 추가 3-5일 소요 가능하므로 버퍼 포함 최대 2주.

**전제 조건:**
- [ ] `rpc_service.rs`의 `detected_patterns` 빈 벡터 버그 수정 (RPC 모드 deep analysis 연결)
- [ ] 현재 14일 운영 데이터에서 오탐률 베이스라인 측정

**PoC 작업:**
- [ ] ethrex LEVM `StepRecord` 구조 분석 — AgentContext 각 필드([02_DATA_MODEL.md](./02_DATA_MODEL.md))에 매핑 가능 여부 검증, 누락 정보 식별
- [ ] 기존 fixture TX 3개(Balancer, Bybit, Poly Network)를 수동으로 AgentContext JSON으로 변환
- [ ] 정상 TX 10개도 동일 형식으로 변환 (총 13개로 PoC 검증. Phase 1에서 공격 10 + 정상 10 = 20개+로 확장)
- [ ] Claude API에 직접 프롬프트를 보내 판별 정확도 측정
- [ ] 비용 시뮬레이션: 실제 토큰 수 기반 req당 비용 산출
- [ ] `is_suspicious_confidence_threshold` 에스컬레이션 비율 추정
- [ ] `anthropic-sdk-rust` API 호환성 검증 (streaming, JSON mode, prompt caching). 미지원 시 reqwest 직접 호출로 전환 가능 여부 확인
- [ ] 결과 문서화 → PoC 정확도 80% 미만이면 Phase 1 중단

**인원:** 1인 풀타임

## Phase 1: MVP (6-8 weeks 개발 + 1-2 weeks 스테이징 = 총 7-10 weeks)

AI 판단 엔진의 핵심 파이프라인을 구축한다.

> **일정 변동 요인:** 6주(최선) = StepRecord가 call_graph, storage_mutations 등을 직접 제공하는 경우. 8주(최악) = StepRecord에서 수동 opcode 파싱이 필요하거나, Hallucination Guard 정밀도 조정에 추가 반복이 필요한 경우.

**전제 조건:**
- Phase 0 PoC 정확도 80% 이상
- `rpc_service.rs` 버그 수정 완료

**인원 가정:** 1인 풀타임

### Phase 1-1: 기반 구조 (1-1.5 weeks)

- [ ] `ai_agent` feature flag 추가 (Cargo.toml)
- [ ] `anthropic-sdk-rust` 의존성 추가
- [ ] `src/sentinel/ai/` 모듈 구조 생성 (상세는 04_PROJECT_SPEC.md 참조)
- [ ] CostTracker 구현 (파일 기반 영속성, 일/월 리셋, 시간당 rate limit)
- [ ] Circuit breaker 구현 (연속 5회 API 실패 시 10분간 비활성화, `auto_pause.rs` 패턴 재사용)
- [ ] 환경변수 `ANTHROPIC_API_KEY` 검증
- [ ] 기반 구조 테스트 (types serialization, cost tracking, circuit breaker)

### Phase 1-2: 컨텍스트 추출기 (2-3 weeks)

> ethrex LEVM의 `StepRecord` 구조가 필요한 정보를 직접 제공하는지에 따라 난이도가 크게 달라진다.
> `StepRecord` 분석이 Phase 0에서 완료되어 있어야 한다.

- [ ] `src/sentinel/ai/context.rs` — ContextExtractor 구현
- [ ] opcode trace → AgentContext 변환 로직
  - call_graph 추출 (CALL/STATICCALL/DELEGATECALL/CALLCODE) + **input_selector (4byte)**
  - storage_mutations 추출 (SSTORE)
  - erc20_transfers 추출 (LOG3 + Transfer topic)
  - log_events 추출 (Transfer 외 이벤트: Approval, Swap, Sync 등)
  - eth_transfers 추출 (CALL with value)
  - revert_count 집계
  - delegatecalls 추출
  - contract_creations 추출 (CREATE/CREATE2)
- [ ] AgentContext → JSON 직렬화 (~2-5KB 타겟)
- [ ] 기존 fixture TX로 추출기 테스트 (Phase 0 수동 변환 결과와 대조)

### Phase 1-3: AI 판단 엔진 (2 weeks)

- [ ] `src/sentinel/ai/judge.rs` — AiJudge 구현
- [ ] Haiku 스크리닝 프롬프트 작성 + 반복 실험
- [ ] Sonnet 심층 분석 프롬프트 작성 + 반복 실험
- [ ] 2-tier 파이프라인 (Haiku → `is_suspicious_confidence >= 0.6` → Sonnet)
- [ ] AgentVerdict 파싱 (JSON response → struct, `AttackType` enum 매핑)
- [ ] Hallucination Guard: AI evidence가 AgentContext에 존재하는지 프로그래밍적 검증
- [ ] Prompt caching 적용 (시스템 프롬프트 90% 비용 절감)
- [ ] 타임아웃 + 재시도 로직 (3회, exponential backoff)
- [ ] API 장애 시 circuit breaker 연동
- [ ] fixture 20개+ 기반 판단 정확도 테스트 (공격 10 + 정상 10)

### Phase 1-4: 파이프라인 통합 (1-1.5 weeks)

- [ ] Sentinel pipeline에 AI 단계를 **비동기**로 삽입 (2-pass: 규칙 기반 즉시 → AI 보강)
- [ ] 블록당 최대 동시 AI 요청 수 제한 (default: 3)
- [ ] SentinelAlert에 `agent_verdict: Option<AgentVerdict>` 필드 추가
- [ ] Autopsy에 `--ai` CLI 플래그 추가
- [ ] 포렌식 리포트에 AI 판단 섹션 추가
- [ ] TOML 설정 항목 추가 (`[ai]` 섹션)
- [ ] 통합 테스트 (전체 파이프라인 e2e)
- [ ] `examples/sentinel_ai_demo.rs` 데모

**Phase 1-4 완료 후 스테이징 (1-2 weeks 추가):**
- [ ] AI 통합 Sentinel 메인넷 스테이징 배포
- [ ] 1-2주 운영 데이터 수집 (Phase 2 프롬프트 튜닝 데이터 확보)

**Phase 1 → Phase 2 착수 기준:**
- AI 판단 정확도 80%+ (fixture 기반)
- 월 비용 추정 $200 미만
- Circuit breaker 정상 작동 확인
- 메인넷 스테이징 1주+ 무장애 운영

## Phase 2: 최적화 (2-3 weeks)

정확도와 비용 효율을 개선한다.

### Phase 2-1: 프롬프트 최적화 (1 week)

- [ ] 메인넷 운영 데이터 기반 프롬프트 튜닝
- [ ] Few-shot 예제 추가 (알려진 공격 TX 5-10개)
- [ ] 오탐 패턴 분석 및 프롬프트 보정
- [ ] 프롬프트 버전 관리 시스템 (TOML 기반)

### Phase 2-2: 컨텍스트 압축 + 비용 절감 (1 week)

- [ ] 대형 TX 컨텍스트 압축 전략 (토큰 절약)
- [ ] call_graph depth 제한 + 요약
- [ ] 중복 storage_mutation 병합
- [ ] 컨텍스트 크기별 비용 분석
- [ ] Prompt caching 효율 모니터링 + 최적화

### Phase 2-3: 메트릭 & 대시보드 (0.5-1 week)

- [ ] AI 관련 Prometheus 메트릭 추가
  - `argus_ai_requests_total{model, result}`
  - `argus_ai_latency_seconds{model}`
  - `argus_ai_cost_usd_total`
  - `argus_ai_budget_remaining_usd`
  - `argus_ai_hallucination_guard_rejected_total`
- [ ] 대시보드에 AI 판단 결과 표시
- [ ] 비용 알림 (50%, 80%, 100% 임계값)

**Phase 2 → Phase 3 착수 기준:**
- 오탐 감소율 30%+ (14일 메인넷 비교)
- 월 비용 실측 $150 이내
- Hallucination Guard 거부율 < 10% (절대 상한 20%. PoC에서 초기 거부율 측정 후 확정)

## Phase 3: 고도화 (3-4 weeks)

고급 탐지 기능을 추가한다.

### Phase 3-1: Tool-use 통합 (2 weeks)

- [ ] AI가 외부 도구를 호출하여 추가 정보 수집
  - Etherscan 컨트랙트 소스 조회
  - 4byte.directory 함수 시그니처 조회
  - 컨트랙트 생성 시점 조회 (신규 컨트랙트 = 높은 위험)
- [ ] Tool 호출 비용 포함 관리

### Phase 3-2: Sandwich/MEV 탐지 (1-2 weeks)

- [ ] 블록 내 멀티-TX 컨텍스트 분석
- [ ] TX 순서 기반 sandwich attack 패턴 감지
- [ ] MEV bot 식별 휴리스틱

### Phase 3-3: 학습 루프 (1-2 weeks)

- [ ] 운영자 피드백 수집 API (true positive / false positive 태깅) — **MVP: 이것만 1주**
- [ ] 피드백 기반 few-shot 예제 자동 업데이트 (피드백 수집 후 추가)
- [ ] 주간 정확도 리포트 자동 생성 (피드백 수집 후 추가)

## 이후 방향

Phase 3 완료 후 메인넷 6개월 운영 데이터를 기반으로 다음 방향을 재평가한다:

- **Self-hosted 모델:** 비용 절감 + 분석 패턴 노출 제거. Ollama 기반 로컬 추론 검토
- **멀티체인 확장:** L2 (OP Stack, Arbitrum) 및 ethrex L2 지원
- **Fine-tuning:** 6개월 피드백 데이터로 EVM 공격 탐지 특화 모델 학습
- **유지보수:** 프롬프트 분기별 검토, Anthropic API 변경 대응, fixture 확장
