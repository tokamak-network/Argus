# Argus Roadmap

**[Architecture Diagram](argus-architecture.html)** — 모듈별 파일 매핑이 포함된 인터랙티브 아키텍처 맵

## 현실 진단

Argus의 코드 품질은 높지만, 외부 경쟁력에는 구조적 문제가 있다.

| 문제 | 심각도 | 요약 |
|------|--------|------|
| ethrex 의존성 | **치명적** | ethrex 클라이언트 시장 점유율 ~0%. "L1 노드 통합" 강점이 발현될 곳이 없음 |
| 프로덕션 검증 0건 | **치명적** | 모든 케이스 스터디가 가정법("would have"). 실제 탐지 실적 0건 |
| 1인 개발 체제 | **높음** | 외부 기여자 0, 이슈 0, 커뮤니티 채널 없음. 버스 팩터(Bus Factor) = 1 |
| 진입 장벽 | **높음** | Rust 1.85+ 빌드 필수. 5분 안에 실제 결과를 볼 수 없음 |
| 올인원 리스크 | **중간** | 3개 모듈 모두 전문 경쟁자 대비 열위. Sentinel에 집중 필요 |

---

## Phase 0: 기반 정비 (즉시 ~ 2주)

목표: **"5분 안에 실제 결과를 볼 수 있는 경로"를 만든다.**

| # | 항목 | 상태 |
|---|------|------|
| 0-1 | Docker Hub 이미지 퍼블리시 (`docker run tokamak/argus-demo`) | GitHub Secrets 등록 대기 |
| 0-2 | CONTRIBUTING.md 작성 | 완료 |
| 0-3 | GitHub Discussions 활성화 | 미착수 |
| 0-4 | 실제 메인넷 해킹 TX 3-5건을 test fixtures로 추가 | 미착수 |
| 0-5 | `good first issue` 라벨로 외부 기여 가능 이슈 5개 생성 | 미착수 |
| 0-6 | 과거 해킹 TX 1-2건 리플레이 스모크 테스트 — 파이프라인 작동 확인 수준 | 미착수 |

---

## Phase 1: ethrex 탈피 — RPC 독립 + Reth ExEx (Q2 2026)

목표: **ethrex 없이도 Argus를 사용할 수 있게 하고, Reth 생태계 진입을 준비한다.**

현재 Argus는 ethrex LEVM 위에서만 동작한다. ethrex의 시장 점유율이 ~0%인 상황에서 이것은 치명적 제약이다.

### 해결 방안 — 두 트랙 순차 진행 (기여자 합류 시 병렬 전환)

```
현재: Argus → ethrex LEVM (내장) → 블록 분석

트랙 A: Argus → RPC 엔드포인트 (외부) → 블록 분석  ← 1급 시민으로 승격
트랙 B: Argus → Reth ExEx (플러그인) → 블록 분석    ← PoC 병렬 진행

유지:  Argus → ethrex LEVM (내장) → 블록 분석       ← 최적 성능 경로로 유지
```

| # | 항목 | 설명 | 우선순위 |
|---|------|------|----------|
| 1-1 | **RPC 기반 Sentinel 모드** | 임의의 Ethereum RPC 엔드포인트에 연결하여 새 블록을 폴링, 각 TX를 pre-filter + deep analysis. ethrex 불필요 | **1순위** — 사용자 기반 확대의 전제 조건 |
| 1-2 | **Autopsy CLI 개선** | `argus autopsy --tx 0x... --rpc https://eth.llamarpc.com` 한 줄로 메인넷 TX 포렌식 분석. 이미 RPC 클라이언트 존재하므로 CLI 개선만 필요 | 높음 |
| 1-3 | **Reth ExEx PoC** | Reth의 Execution Extensions으로 Sentinel을 통합할 수 있는지 PoC. Reth 시장 점유율 성장 중이며, "노드 내장" 비전을 현실화할 가장 유망한 경로 | **2순위** — 1-1 완료 후 착수, 또는 외부 기여자 합류 시 병렬 가능 |

### 왜 Reth ExEx를 "장기 검토"에서 승격했는가

- ethrex에 계속 종속되면 TAM(Total Addressable Market)이 0에 수렴한다
- Reth는 Rust 기반 Ethereum 클라이언트 중 가장 빠르게 성장 중이다
- ExEx를 통한 보안 플러그인은 Argus의 "노드 내장" 비전을 실현할 수 있는 가장 현실적인 경로다
- PoC 수준이라면 리소스 부담이 크지 않다

### 완료 기준

**트랙 A (RPC 모드)** — Phase 1의 핵심 마일스톤:
- **모든 Ethereum 노드 운영자**가 Argus를 사용할 수 있다 (ethrex 한정 → 전체 생태계)
- Alchemy/Infura 같은 RPC 프로바이더 사용자도 대상이 된다
- `docker run tokamak/argus --rpc https://...` 한 줄로 시작 가능

**트랙 B (Reth ExEx PoC)** — 트랙 A 완료 후 또는 기여자 합류 시:
- Reth ExEx로 Sentinel pre-filter가 작동하는 최소 데모 완성
- "Reth 노드에서 Argus 보안 레이어를 활성화할 수 있다"를 한 문장으로 증명

---

## Phase 2: 프로덕션 실적 축적 (Q2-Q3 2026)

목표: **"would have detected"를 "did detect"로 바꾼다.**

| # | 항목 | 설명 |
|---|------|------|
| 2-1 | **메인넷 14일 연속 운영** | AWS ECS Fargate에서 RPC 모드 Sentinel을 메인넷에 연결, 14일간 구동. 스캔 블록 수, 의심 TX 수, 탐지 결과 기록. [배포 가이드](deployment.md) 참조 |
| 2-2 | **탐지 실적 문서화** | "2026년 Q2, 메인넷에서 X개 블록 스캔, Y건 의심 TX 탐지, Z건 확인" — 첫 실적 보고서 |
| 2-3 | **과거 해킹 TX 체계적 리플레이 검증** | Balancer, Bybit, Euler 등 5건 이상의 유명 해킹 TX를 Autopsy에서 실행, 정량 결과(탐지율, 신뢰도, 지연 시간)를 보고서로 작성. Phase 0-6 스모크 테스트와 달리 체계적 벤치마크 |
| 2-4 | **지연 벤치마크(Latency Benchmark)** | Pre-filter μs/tx, Deep Analyzer ms/tx 수치 측정 및 공개 |

### 성공 기준

- "Argus detected X suspicious transactions on Ethereum mainnet over 14 days" — 이 한 문장을 README에 쓸 수 있으면 Phase 2 완료

---

## Phase AI-0: LLM 통합 PoC 검증 — PASS (2026-03-05 완료)

목표: **LLM이 EVM opcode trace를 분석하여 공격을 탐지할 수 있는지 검증한다.**

상세 설계: [`PRD/`](../PRD/README.md) 참조 (5개 문서). PoC 결과: [`docs/ai-agent-poc-report.md`](ai-agent-poc-report.md)

| # | 항목 | 설명 | 상태 |
|---|------|------|------|
| AI-0-1 | **StepRecord→AgentContext 매핑 분석** | ethrex LEVM StepRecord가 call_graph, storage_mutations 등을 제공하는지 검증 | ✅ 완료 |
| AI-0-2 | **Fixture 변환** | 공격 TX 3개 + 정상 TX 10개 → AgentContext JSON (13개) | ✅ 완료 |
| AI-0-3 | **LiteLLM (Gemini) 정확도 측정** | 13개 fixture로 gemini-3-flash/pro 판별 정확도 **100%** 달성 (목표 80%) | ✅ 완료 |
| AI-0-4 | **SDK 호환성 검증** | anthropic-sdk-rust 부적합 → LiteLLM proxy (OpenAI-compatible) 채택 | ✅ 완료 |
| AI-0-5 | **비용 시뮬레이션** | $0.009-0.016/req, 월 $67-250 (캐시율 의존). $150 예산 내 운영 가능 | ✅ 완료 |

**전제 조건:** `rpc_service.rs` detected_patterns 버그 ✅ 수정 완료

**결과:** 정확도 100% (13/13) — Phase AI-1 MVP 착수 승인

Phase AI-1 (MVP, 6-8주) → AI-2 (최적화, 2-3주) → AI-3 (고도화, 3-4주)

---

## Phase 3: 채택 확대 (Q3-Q4 2026)

목표: **첫 번째 외부 사용자를 확보한다.**

| # | 항목 | 설명 |
|---|------|------|
| 3-1 | **crates.io 퍼블리시** | `cargo install argus`로 설치 가능 |
| 3-2 | **Reth ExEx 통합** (Phase 1-3 PoC 결과에 따라) | Reth 사용자가 플러그인으로 Sentinel 활성화 |
| 3-3 | **Sentinel에 집중** | 3개 모듈 중 가장 차별화된 Sentinel에 리소스 집중. "올인원"보다 "Ethereum L1에 특화된 오픈소스 런타임 보안 도구" 포지셔닝 |
| 3-4 | **커뮤니티 성장** | Discord/Telegram 개설, 정기 보안 분석 콘텐츠 발행 |

---

## 전략 전환 요약

| 기존 방향 | 전환 방향 |
|-----------|----------|
| GitHub 스타 최적화 (마케팅) | 프로덕션 실적 최적화 (제품) |
| ethrex 전용 | RPC 독립 모드 1급 시민 + Reth ExEx 병렬 |
| 올인원 (3모듈 동시) | Sentinel 집중, 나머지는 보조 |
| 합성 데모 | 실제 메인넷/테스트넷 데이터 |
| 케이스 스터디 (가정법) | 탐지 실적 보고서 (사실) |
| "써보려면 Rust 빌드" | "docker run 한 줄" |
| "L1 노드에서 차단" (검증 안 됨) | "오픈소스 셀프호스팅 런타임 보안" (검증 가능) |
| Reth ExEx 장기 검토 | Reth ExEx PoC Phase 1 순차 (기여자 합류 시 병렬) |
| 소규모 팀 = 중간 리스크 | 1인 체제 = 높은 리스크. 즉시 해소 시작 |
