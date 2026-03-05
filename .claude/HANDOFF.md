# Argus Handoff

## 프로젝트 개요

Argus는 Ethereum 실시간 공격 탐지 + 사후 포렌식 + 타임트래블 디버거.
Rust + ethrex LEVM 기반. AWS ECS Fargate에서 메인넷 스캔 운영 중.

- **레포**: https://github.com/tokamak-network/Argus
- **테스트**: 450 passed, 18 ignored (RPC 필요)
- **배포**: ECS Fargate (ap-northeast-2), ECR 이미지

## 현재 상태 (2026-03-05)

### 미커밋 변경 (도살자 리뷰 수정 6건)

`3f59820` 커밋 이후 Devil's Advocate 코드 리뷰 (7.54/10) 수정사항:

| 파일 | 수정 내용 |
|------|----------|
| `src/sentinel/config.rs` | `to_whitelist_entry()`에 score_modifier 범위 검증 추가, `validate()`에 `"Dex"` 케이스 추가, 테스트 2개 추가 |
| `src/sentinel/service.rs` | Store 모드 `with_mempool()`에 `WhitelistEngine` 파라미터 추가, `PreFilter::with_whitelist()` 사용 |
| `src/sentinel/tests.rs` | 조건부 assertion (`if let Some`) → `match` 양쪽 경로 모두 assertion |
| `examples/sentinel_realtime_demo.rs` | `with_mempool()` 호출에 `WhitelistEngine::empty()` 추가 |
| `PRD/01_PRD.md` | Phase 1 확정 항목 분리, NEEDS CLARIFICATION → Phase 2-3만 남김 |
| `PRD/04_PROJECT_SPEC.md` | 결정 완료 섹션 추가, stage_multiplier 초기값 명시 |

**상태**: cargo check + cargo test (450 passed) + clippy + fmt 전부 통과.
**다음**: 커밋 후 ECS 재배포 가능.

### 완료된 Phase 전체 목록

| Phase | 내용 | 상태 |
|-------|------|------|
| Phase 0 | 초기 설정 (Docker, CONTRIBUTING, fixtures, good-first-issue) | 완료 |
| Phase 1-1 | RPC 독립 모드 (rpc_poller, rpc_replay, rpc_service) | 완료 |
| Phase 1-2 | Autopsy CLI 개선 (DRY, aliases, --interactive) | 완료 |
| Phase 2-1 | 배포 인프라 (CLI, metrics, Dockerfile, ECS) | 완료 |
| Phase 2-1+ | 메인넷 버그 수정 (config 로딩, TX 해시 불일치) | 완료 |
| **FP Phase 1** | **DeFi 화이트리스트 엔진** (whitelist.rs, config 통합, 35+ 테스트) | **완료** |
| Phase 2-2 | 메인넷 14일 운영 실적 | 진행중 |

### 이번 세션 핵심 작업: DeFi 화이트리스트 엔진

**문제**: 25건 알림 중 20건이 false positive (80% 오탐률). Balancer Vault flash loan 정상 arb가 Critical로 분류.

**해결**: TOML 설정 기반 DeFi 프로토콜 화이트리스트 엔진.

**신규/수정 파일**:
- `src/sentinel/whitelist.rs` (370줄) — WhitelistEngine, WhitelistConfig, serde helpers
- `src/sentinel/config.rs` (+450줄) — WhitelistTomlConfig, TOML↔도메인 변환, 검증
- `src/sentinel/pre_filter.rs` (+38줄) — 화이트리스트 scoring 통합
- `src/sentinel/types.rs` — threshold 변경 (Critical≥0.85, High≥0.65), `whitelist_matches` 필드
- `src/sentinel/rpc_service.rs` — RPC 모드 화이트리스트 연결
- `src/sentinel/service.rs` — Store 모드 화이트리스트 연결
- `src/sentinel/tests.rs` (+600줄) — 35+ 신규 테스트
- `PRD/` (5개 문서) — 오탐률 개선 프로젝트 PRD

**핵심 설계 결정**:
1. **2계층 TOML**: 문자열 기반 `WhitelistTomlConfig` (TOML 파싱) → 타입 기반 `WhitelistEntry` (런타임)
2. **Score 공식**: `score = (base_score + wl_modifier).clamp(0.0, 1.0)`, modifier는 매칭된 entries의 합 ([-1.0, 0.0] clamp)
3. **FlashLoan 단독 가드**: `FlashLoanSignature`만으로는 알림 불가 — 최소 1개 추가 reason 필요
4. **Graceful 에러**: 잘못된 TOML 항목은 skip + eprintln 경고, 전체 실패 안 함

### 도살자 리뷰 결과

코드 7.14/10 (재훈련 필요) + 산문 8.4/10 (출판 가능) = 가중 평균 **7.54/10 (수용 가능)**

**수정 완료 (6건)**:
1. `to_whitelist_entry()` score_modifier 범위 검증 — 양수 modifier 차단
2. `validate()` "Dex" 케이스 일관성 — parser와 validator 동기화
3. Store 모드 화이트리스트 연결 — `PreFilter::with_whitelist()` 사용
4. 조건부 assertion 제거 — match로 양쪽 경로 모두 검증
5. PRD NEEDS CLARIFICATION 정리 — Phase 1 확정 항목 분리
6. Scoring 알고리즘 중복 제거 — PRD→SPEC 교차 참조

**미수정 (낮은 우선순위)**:
- config.rs 900줄 (800줄 초과) — whitelist TOML 파서 분리 고려
- O(n) 주소 탐색 → HashMap 전환 (현재 규모에서는 불필요)
- NaN guard (TOML에서 NaN 불가, 이론적 우려)

## 남은 작업 (우선순위 순)

1. **이번 수정사항 커밋** — 도살자 리뷰 수정 6건
2. **ECS 재배포** (v0.2.0) — 화이트리스트 + `--alert-file` 활성화, 시드 데이터 포함
3. **Phase 2-2 완료** — 메인넷 14일 운영 후 탐지 실적 정리
4. **FP Phase 2** — 다단계 공격 매핑 (Funding→Exploitation→Drain) + Profit extraction 탐지
5. **FP Phase 3** — Historical labeling 백테스트 (precision/recall 자동 측정)

## AWS 인프라

| 항목 | 값 |
|------|---|
| 리전 | ap-northeast-2 (서울) |
| ECR | `381492157878.dkr.ecr.ap-northeast-2.amazonaws.com/argus` |
| ECS Cluster | `argus` |
| Service | `argus-sentinel` |
| Task Definition | `argus-sentinel` (0.5 vCPU, 1GB) |
| Secret | `argus/rpc-url` (Secrets Manager) |
| SG | `sg-053b4fcde9f4f46f5` (inbound 9090) |
| Log Group | `/ecs/argus-sentinel` |

## 빌드 명령어

```bash
cargo check --all-features
cargo test --all-features              # 450 tests
cargo clippy --all-features -- -D warnings
cargo fmt --check

# 예제
cargo run --example sentinel_rpc_demo --features sentinel,autopsy
cargo run --example sentinel_realtime_demo

# CLI
cargo run --bin argus --features cli -- sentinel \
  --rpc https://eth-mainnet.g.alchemy.com/v2/KEY \
  --config sentinel.toml --metrics-port 9090

# 배포
./scripts/ecs-deploy.sh --tag v0.2.0 --region ap-northeast-2
```

## 핵심 의사결정 기록

1. **LEVM 의존성 유지**: ethrex_levm 17파일 51줄 직접 참조. revm 포팅은 2-4주. Q3에 ethrex L2 동향 보고 결정.
2. **Phase 2 우선 (메인넷 실적)**: "would have detected" → "did detect" 전환이 최우선. Phase 1-3 (노드 내장)은 실적 없이 설득력 부족.
3. **TOML 정적 화이트리스트**: DeFiLlama 등 외부 API 대신 TOML 설정으로 충분. 네트워크 의존성 추가 없음.
4. **2계층 설정 구조**: 문자열 TOML → 타입 도메인. 파싱 에러는 skip (전체 실패 방지).
