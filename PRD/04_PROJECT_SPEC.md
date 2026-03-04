# Argus Sentinel 오탐률 개선 -- 프로젝트 스펙

> AI가 코드를 짤 때 지켜야 할 규칙과 절대 하면 안 되는 것.
> 이 문서를 AI에게 항상 함께 공유하세요.

---

## 기술 스택

| 영역 | 선택 | 이유 |
|------|------|------|
| 언어 | Rust 1.85+ (edition 2024) | 기존 코드베이스. 타입 안전성 + 성능 |
| EVM 엔진 | ethrex LEVM (rev 03fc1858) | 기존 의존성. opcode-level 분석 |
| HTTP 서버 | axum | 기존 Sentinel 서버 |
| 비동기 런타임 | tokio | 기존 폴링 + WS 파이프라인 |
| 설정 | TOML (toml crate) | 기존 config.rs 패턴. 화이트리스트 추가 |
| 테스트 | cargo test (built-in) | CI 통합, fixture 기반 |
| 배포 | AWS ECS Fargate (ap-northeast-2) | 기존 인프라 |
| 컨테이너 | Docker | 기존 Dockerfile |

---

## 프로젝트 구조 (변경 대상)

```
src/sentinel/
├── whitelist.rs       # [신규] WhitelistConfig, WhitelistCategory, TOML 파서
├── profit_analyzer.rs # [신규] ProfitFlow 분석기
├── types.rs           # [수정] AttackStage enum, SuspicionReason 확장, SentinelAlert 확장
├── pre_filter.rs      # [수정] 화이트리스트 체크 + 다단계 매핑 통합
├── pipeline.rs        # [수정] profit 분석 단계 추가
├── config.rs          # [수정] whitelist 섹션 파싱
├── mod.rs             # [수정] 새 모듈 등록
└── ...                # 기존 파일 유지

src/tests/
├── backtest.rs        # [신규] 백테스트 러너
└── fixtures/          # [신규] 공격/정상 TX fixture 데이터
```

---

## 절대 하지 마 (DO NOT)

> AI에게 코드를 시킬 때 이 목록을 반드시 함께 공유하세요.

- [ ] **기존 SentinelAlert JSON 직렬화를 깨뜨리지 마** — 새 필드는 `#[serde(default)]`로 추가. 대시보드 API 호환성 유지
- [ ] **기존 테스트 397개를 깨뜨리지 마** — 새 로직은 새 테스트로 검증
- [ ] **하드코딩된 주소를 소스 코드에 넣지 마** — 모든 화이트리스트 주소는 TOML 설정
- [ ] **외부 API 호출을 추가하지 마** — DeFiLlama, Etherscan 등 네트워크 의존성 금지
- [ ] **pre_filter의 기존 로직을 삭제하지 마** — 화이트리스트와 다단계 매핑은 기존 로직 위에 추가하는 레이어
- [ ] **unsafe 코드를 사용하지 마** — 기존 코드베이스에 unsafe 없음
- [ ] **clippy 경고를 무시하지 마** — `cargo clippy --all-features -- -D warnings` 통과 필수
- [ ] **feature gate 없이 새 의존성을 추가하지 마** — 기존 sentinel feature 안에서만
- [ ] **TOML 파서에 unwrap()을 쓰지 마** — 설정 파싱 실패는 graceful error로 처리
- [ ] **테스트에서 실제 RPC를 호출하지 마** — fixture 기반으로만 (CI에서 RPC 없음)

---

## 항상 해 (ALWAYS DO)

- [ ] **변경하기 전에 기존 코드를 읽어라** — pre_filter.rs, types.rs, config.rs 구조 파악 먼저
- [ ] **새 타입은 `#[derive(Debug, Clone, Serialize, Deserialize)]`** — 기존 패턴 준수
- [ ] **에러는 `thiserror`로 정의** — `DebuggerError` enum에 variant 추가
- [ ] **테스트 먼저 작성 (TDD)** — RED → GREEN → IMPROVE
- [ ] **cargo clippy + cargo fmt 실행** — 커밋 전 필수
- [ ] **새 필드에 `#[serde(default)]` 적용** — 기존 JSONL 데이터와 역호환
- [ ] **기존 fund_flow 데이터 활용** — ProfitFlow는 이미 있는 fund_flows 필드 기반
- [ ] **WhitelistConfig 로드 실패 시 빈 리스트로 폴백** — 화이트리스트 없이도 동작해야 함

---

## 테스트 방법

```bash
# 전체 테스트 (기존 + 신규)
cargo test --all-features

# 화이트리스트 테스트만
cargo test whitelist --all-features

# 다단계 매핑 테스트만
cargo test attack_stage --all-features

# 백테스트만
cargo test backtest --all-features

# Clippy 검사
cargo clippy --all-features -- -D warnings

# 포맷 검사
cargo fmt --check
```

---

## 배포 방법

```bash
# 1. 로컬 빌드 + 테스트
cargo test --all-features
cargo clippy --all-features -- -D warnings

# 2. Docker 빌드
docker build -t argus:v0.3.0 .

# 3. ECS 배포
./scripts/ecs-deploy.sh --tag v0.3.0 --region ap-northeast-2

# 4. 배포 후 확인
curl http://<TASK_IP>:9090/health
curl http://<TASK_IP>:9090/sentinel/metrics
curl http://<TASK_IP>:9090/sentinel/history
```

---

## 환경변수

| 변수명 | 설명 | 어디서 발급 |
|--------|------|------------|
| `ARGUS_RPC_URL` | 메인넷 RPC endpoint | Alchemy Dashboard |
| `ARGUS_METRICS_PORT` | 메트릭 서버 포트 (기본 9090) | 자체 설정 |

> .env 파일에 저장. 절대 GitHub에 올리지 마세요.

---

## Scoring 알고리즘 (변경 후)

```
base_score = 기존 pre_filter 계산값

# Phase 1: 화이트리스트 감점
for each suspicion_reason:
    if reason.contract in whitelist:
        base_score += whitelist_entry.score_modifier  # 음수값

# Phase 2: 다단계 보정
stages_confirmed = unique(reason.stage for reason in reasons)
if len(stages_confirmed) == 1:
    stage_multiplier = 0.6   # 1단계만 → 감점
elif len(stages_confirmed) == 2:
    stage_multiplier = 1.0   # 2단계 → 유지
elif len(stages_confirmed) >= 3:
    stage_multiplier = 1.3   # 3단계+ → 가점

# Phase 2: Profit 보정
if profit_flow.is_circular:
    profit_modifier = -0.2   # 정상 arb → 감점
elif profit_flow.drain_target.is_some():
    profit_modifier = +0.15  # drain 패턴 → 가점
else:
    profit_modifier = 0.0

final_score = clamp(base_score * stage_multiplier + profit_modifier, 0.0, 1.0)

# Priority 결정
if final_score >= 0.85:  Critical
elif final_score >= 0.65: High
else:                     Medium
```

---

## [NEEDS CLARIFICATION]

- [ ] 화이트리스트 로드 시점: Sentinel 시작 시 1회 vs 주기적 리로드
- [ ] ProfitFlow에서 "circular" 판정의 hop depth 제한 (1-hop? 3-hop?)
- [ ] Stage 매핑이 확정되지 않은 새 SuspicionReason 타입이 추가될 때의 기본 stage
