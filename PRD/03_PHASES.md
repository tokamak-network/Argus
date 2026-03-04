# Argus Sentinel 오탐률 개선 -- Phase 분리 계획

> 한 번에 다 만들면 복잡해져서 품질이 떨어집니다.
> Phase별로 나눠서 각각 측정 가능한 precision 개선을 달성합니다.

---

## Phase 1: 화이트리스트 엔진 (1-2일)

### 목표
즉각적인 오탐 감소. Balancer Vault 등 알려진 DeFi 프로토콜의 정상 TX를 필터링하여 precision 20% → 50%+ 달성.

### 기능
- [ ] `WhitelistConfig` 타입 정의 (`sentinel/whitelist.rs`)
- [ ] `WhitelistCategory` enum 정의 (FlashLoan, DEX, Lending, Bridge)
- [ ] TOML 파서 구현 (`[sentinel.whitelist]` 섹션)
- [ ] `pre_filter.rs`에 화이트리스트 체크 로직 통합
- [ ] `score_modifier` 적용 로직 (화이트리스트 매칭 시 score 감점)
- [ ] `FlashLoanSignature` 단독 트리거 제거 (flash loan만으로는 Critical 불가)
- [ ] `suspicion_threshold` 0.7 → 0.85 상향
- [ ] 테스트 10건+ (화이트리스트 매칭/미매칭, score 감점, threshold 경계)
- [ ] ECS 재배포 + 24시간 모니터링

### 데이터
- WhitelistConfig (TOML에서 로드)
- SuspicionReason.whitelisted 필드 추가

### 변경 대상 파일
| 파일 | 변경 |
|------|------|
| `src/sentinel/whitelist.rs` | 신규 — 화이트리스트 타입 + TOML 파서 |
| `src/sentinel/pre_filter.rs` | 수정 — 화이트리스트 체크 + score_modifier 적용 |
| `src/sentinel/config.rs` | 수정 — whitelist 섹션 파싱 추가 |
| `src/sentinel/types.rs` | 수정 — SuspicionReason에 whitelisted 필드 |
| `src/sentinel/mod.rs` | 수정 — whitelist 모듈 등록 |
| `src/tests/` | 신규 — 화이트리스트 테스트 |

### "진짜 동작" 체크리스트
- [ ] 기존 397 테스트 전부 통과
- [ ] 새 테스트 10건+ 통과
- [ ] ECS에서 Balancer Vault arb TX가 Critical에서 제외됨
- [ ] 24시간 운영 후 오탐률 50% 이하 확인

### Phase 1 시작 프롬프트
```
이 PRD를 읽고 Phase 1을 구현해주세요.
@PRD/01_PRD.md
@PRD/02_DATA_MODEL.md
@PRD/04_PROJECT_SPEC.md

Phase 1 범위:
- WhitelistConfig 타입 + TOML 파서
- pre_filter.rs에 화이트리스트 체크 통합
- score_modifier 적용
- FlashLoan 단독 트리거 제거
- suspicion_threshold 0.7 → 0.85
- 테스트 10건+

반드시 지켜야 할 것:
- 04_PROJECT_SPEC.md의 "절대 하지 마" 목록 준수
- 기존 397 테스트가 깨지면 안 됨
- 새 모듈은 sentinel/whitelist.rs에 생성
```

---

## Phase 2: 다단계 공격 매핑 + Profit 분석 (3-5일)

### 전제 조건
- Phase 1이 ECS에 배포되고 24시간 안정 운영된 상태

### 목표
precision 50% → 70%+ 달성. flash loan 사용 여부가 아닌 "공격의 완결성"으로 판단.

### 기능
- [ ] `AttackStage` enum 정의 (Funding, Preparation, Exploitation, MoneyLaundering)
- [ ] `SuspicionReason.stage` 필드 추가
- [ ] 기존 reason 타입별 stage 매핑 테이블
  - FlashLoanSignature → Funding
  - MultipleErc20Transfers → Exploitation
  - HighValueWithRevert → Exploitation
  - SelfDestruct → MoneyLaundering
  - KnownContractInteraction → (화이트리스트 결과에 따라)
  - UnusualGasPattern → Preparation or MoneyLaundering
- [ ] 복합 단계 검증 로직: 확인된 단계 수 → priority 재계산
  - 1단계: Medium (감시 대상)
  - 2단계: High (주의 필요)
  - 3-4단계: Critical (실제 공격 가능성 높음)
- [ ] `ProfitFlow` 타입 구현
- [ ] fund_flow 데이터에서 circular 패턴 탐지 (sender → ... → sender = arb)
- [ ] drain 패턴 탐지 (피해 컨트랙트에서 새 주소로 자금 이동)
- [ ] `SentinelAlert`에 `attack_stages`, `profit_flow`, `whitelist_matches` 필드 추가
- [ ] alert_priority 재계산 로직 (stages + profit + whitelist 종합)
- [ ] 테스트 15건+ (단계 매핑, profit 분석, priority 재계산)

### 추가 데이터
- AttackStage, ProfitFlow (02_DATA_MODEL.md 참조)
- SentinelAlert 확장 필드

### 변경 대상 파일
| 파일 | 변경 |
|------|------|
| `src/sentinel/types.rs` | 수정 — AttackStage enum, ProfitFlow 구조체, SentinelAlert 확장 |
| `src/sentinel/pre_filter.rs` | 수정 — stage 매핑 + 다단계 검증 로직 |
| `src/sentinel/pipeline.rs` | 수정 — profit 분석 단계 통합 |
| `src/sentinel/profit_analyzer.rs` | 신규 — ProfitFlow 분석기 |
| `src/tests/` | 신규/수정 — 다단계 + profit 테스트 |

### 통합 테스트
- Phase 1 화이트리스트 기능이 여전히 정상 동작하는지 확인
- 화이트리스트 + 다단계 매핑 조합 테스트

### Phase 2 시작 프롬프트
```
Phase 1이 완료된 상태에서 Phase 2를 구현해주세요.
@PRD/01_PRD.md
@PRD/02_DATA_MODEL.md
@PRD/04_PROJECT_SPEC.md

Phase 2 범위:
- AttackStage enum + reason별 stage 매핑
- 복합 단계 검증 (≥2단계 = Critical)
- ProfitFlow 분석기 (circular vs drain)
- SentinelAlert 확장 필드
- alert_priority 재계산

반드시 지켜야 할 것:
- Phase 1 화이트리스트가 정상 동작
- 기존 전체 테스트 통과
- ProfitFlow는 fund_flow 데이터 기반 (추가 RPC 호출 없음)
```

---

## Phase 3: 백테스트 검증 (3-5일)

### 전제 조건
- Phase 1 + 2가 ECS에서 안정적으로 운영 중

### 목표
precision/recall을 수치로 증명. 알려진 해킹 TX와 정상 TX로 regression test 구축.

### 기능
- [ ] `HistoricalLabel` 타입 정의 (`#[cfg(test)]`)
- [ ] 공격 TX 데이터셋 수집 (20건+)
  - Euler Finance (2023-03, $197M flash loan)
  - Curve Finance (2023-07, reentrancy)
  - Balancer (2023-08, flash loan)
  - KyberSwap (2023-11, price manipulation)
  - 기타 rekt.news 상위 해킹 TX
- [ ] 정상 TX 데이터셋 수집 (50건+)
  - Balancer Vault 차익거래
  - Uniswap batch swap
  - Aave flash loan repay (정상 청산)
  - 대규모 DEX 거래
- [ ] 백테스트 러너 구현 (`src/tests/backtest.rs`)
  - fixture 기반 (RPC 불필요)
  - pre_filter + 화이트리스트 + 다단계 매핑 파이프라인 실행
  - True Positive / False Positive / False Negative / True Negative 계산
- [ ] Precision/Recall/F1 assertion 테스트
  - `precision >= 0.70`
  - `recall >= 0.60`
- [ ] threshold 튜닝 (score_modifier, suspicion_threshold 최적화)
- [ ] 결과 리포트 생성 (테스트 출력에 포함)

### 추가 데이터
- HistoricalLabel (테스트 전용)
- 공격 TX fixtures (JSONL 또는 Rust 상수)
- 정상 TX fixtures

### 변경 대상 파일
| 파일 | 변경 |
|------|------|
| `src/tests/backtest.rs` | 신규 — 백테스트 러너 + fixtures |
| `src/tests/fixtures/` | 신규 — 공격/정상 TX 데이터 |
| 설정 파일 | 수정 — 튜닝된 threshold/modifier 값 |

### 주의사항
- fixture 데이터는 실제 TX의 receipt + log 정보를 포함해야 함
- RPC 없이 실행 가능하도록 fixture 기반으로 구현
- CI에서 자동 실행되어 regression 방지

### Phase 3 시작 프롬프트
```
Phase 1+2가 완료된 상태에서 Phase 3을 구현해주세요.
@PRD/01_PRD.md
@PRD/02_DATA_MODEL.md
@PRD/04_PROJECT_SPEC.md

Phase 3 범위:
- HistoricalLabel 타입 (#[cfg(test)])
- 공격 TX 20건 + 정상 TX 50건 fixtures
- 백테스트 러너 (precision/recall/F1 측정)
- precision >= 0.70, recall >= 0.60 assertion

반드시 지켜야 할 것:
- RPC 불필요 (fixture 기반)
- CI에서 cargo test로 자동 실행
- 기존 전체 테스트 통과
```

---

## Phase 로드맵 요약

| Phase | 핵심 기능 | 예상 기간 | precision 목표 | 상태 |
|-------|----------|-----------|---------------|------|
| Phase 1 (화이트리스트) | DeFi 화이트리스트 + threshold 조정 | 1-2일 | 50%+ | 시작 전 |
| Phase 2 (다단계+Profit) | 공격 단계 매핑 + 수익 흐름 분석 | 3-5일 | 70%+ | Phase 1 완료 후 |
| Phase 3 (백테스트) | Historical labeling + precision 검증 | 3-5일 | 70%+ 검증 | Phase 2 완료 후 |

```
Phase 1 ──▶ Phase 2 ──▶ Phase 3
(화이트)   (다단계+     (백테스트
            Profit)     검증)
```
