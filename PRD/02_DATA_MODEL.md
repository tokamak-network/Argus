# Argus Sentinel 오탐률 개선 -- 데이터 모델

> 이 문서는 오탐률 개선에 필요한 데이터 구조를 정의합니다.
> 기존 Argus 타입 시스템을 확장하는 형태입니다.

---

## 전체 구조

```
[WhitelistConfig] --적용--> [SentinelAlert]
                                │
                    ┌───────────┼───────────┐
                    │           │           │
            [SuspicionReason] [ProfitFlow] [AttackStage]
                    │
                    └──매핑──> [AttackStage]

[HistoricalLabel] --검증--> [SentinelAlert]
```

---

## 엔티티 상세

### WhitelistConfig (신규)
TOML 설정에서 로드되는 DeFi 프로토콜 화이트리스트 항목. 문 앞의 경비원이 신분증을 확인하듯, 알려진 프로토콜인지 먼저 확인하는 장치.

| 필드 | 타입 | 설명 | 예시 | 필수 |
|------|------|------|------|------|
| address | Address (H160) | 컨트랙트 주소 | `0xBA12222222228d8Ba445958a75a0704d566BF2C8` | O |
| protocol | String | 프로토콜 이름 | `"Balancer Vault"` | O |
| category | WhitelistCategory | 프로토콜 분류 | `FlashLoan` | O |
| score_modifier | f64 | 점수 감점 (-1.0 ~ 0.0) | `-0.4` | O |

**WhitelistCategory enum:**
```
FlashLoan   — flash loan 제공 프로토콜 (Balancer, Aave)
DEX         — 탈중앙 거래소 (Uniswap, Curve)
Lending     — 대출 프로토콜 (Compound, Aave)
Bridge      — 크로스체인 브릿지 (Across, Stargate)
```

### AttackStage (신규)
Forta 방식의 4단계 공격 분류. 범죄 수사에서 "동기-수단-실행-도주"를 추적하는 것과 같은 원리.

| 값 | 설명 | 예시 reason |
|----|------|------------|
| Funding | 공격 자금 조달 | FlashLoanSignature |
| Preparation | 공격 준비 (컨트랙트 배포 등) | SelfDestruct (공격 컨트랙트 생성) |
| Exploitation | 실제 공격 실행 | HighValueWithRevert, ReentrancyPattern |
| MoneyLaundering | 수익 은닉/이체 | UnusualGasPattern (Tornado Cash 등) |

### ProfitFlow (신규)
트랜잭션 내 자금 흐름 분석 결과. CCTV로 돈의 이동 경로를 추적하는 것과 같다.

| 필드 | 타입 | 설명 | 예시 | 필수 |
|------|------|------|------|------|
| sender | Address | TX 발신자 | `0xdead...` | O |
| receiver | Address | 최종 수익 수신자 | `0xbeef...` | O |
| net_profit | U256 | 순이익 (wei) | `1000000000000000000` | O |
| is_circular | bool | 자금이 발신자로 복귀하는지 | `true` = 정상 arb | O |
| drain_target | Option<Address> | 피해 컨트랙트 (drain 시) | `Some(0x...)` | X |

### SuspicionReason (기존 확장)
기존 타입에 stage와 whitelisted 필드를 추가.

| 필드 | 타입 | 설명 | 예시 | 필수 |
|------|------|------|------|------|
| type | String | 의심 유형 (기존) | `"FlashLoanSignature"` | O |
| details | HashMap | 상세 정보 (기존) | `{"contract": "0x..."}` | X |
| **stage** | AttackStage | **공격 단계 매핑 (신규)** | `Funding` | O |
| **whitelisted** | bool | **화이트리스트 매칭 여부 (신규)** | `true` | O |

### SentinelAlert (기존 확장)
기존 알림 타입에 분석 결과 필드 추가.

| 필드 | 타입 | 설명 | 예시 | 필수 |
|------|------|------|------|------|
| tx_hash | String | (기존) | `"0xdead..."` | O |
| block_number | u64 | (기존) | `19234567` | O |
| alert_priority | AlertPriority | (기존) | `Critical` | O |
| suspicion_score | f64 | (기존) | `0.92` | O |
| suspicion_reasons | Vec | (기존) | `[...]` | O |
| **attack_stages** | Vec<AttackStage> | **확인된 공격 단계 (신규)** | `[Funding, Exploitation]` | O |
| **profit_flow** | Option<ProfitFlow> | **수익 흐름 분석 (신규)** | `Some(...)` | X |
| **whitelist_matches** | u32 | **화이트리스트 매칭 횟수 (신규)** | `3` | O |

### HistoricalLabel (신규)
백테스트용 ground truth 레이블. 시험에서 정답지와 같은 역할.

| 필드 | 타입 | 설명 | 예시 | 필수 |
|------|------|------|------|------|
| tx_hash | String | 트랜잭션 해시 | `"0xc310..."` (Euler hack) | O |
| is_attack | bool | 실제 공격 여부 | `true` | O |
| attack_type | String | 공격 유형 | `"flash_loan_exploit"` | O |
| protocol | String | 피해 프로토콜 | `"Euler Finance"` | O |
| loss_usd | f64 | 피해 금액 (USD) | `197_000_000.0` | X |
| source | String | 레이블 출처 | `"rekt.news"` | O |

---

## 관계

- `WhitelistConfig`는 `SentinelAlert`의 `suspicion_score` 계산에 적용됨 (1:N)
- `SuspicionReason`은 정확히 1개의 `AttackStage`에 매핑됨 (N:1)
- `SentinelAlert`는 0~1개의 `ProfitFlow`를 가짐 (1:0..1)
- `HistoricalLabel`은 `SentinelAlert`의 결과와 비교하여 precision/recall 계산 (독립)

---

## 왜 이 구조인가

- **확장성**: 화이트리스트 카테고리와 AttackStage는 enum으로 정의하여 새 유형 추가 시 컴파일 타임 안전성 확보
- **단순성**: 기존 SentinelAlert/SuspicionReason 타입에 필드만 추가하는 최소 변경. 기존 API 호환성 유지 (새 필드는 Option 또는 기본값)
- **분리**: HistoricalLabel은 런타임 코드와 독립적. 테스트 전용 데이터로 프로덕션 바이너리에 포함하지 않음 (`#[cfg(test)]`)

---

## TOML 설정 예시

```toml
[sentinel.whitelist]
entries = [
    { address = "0xBA12222222228d8Ba445958a75a0704d566BF2C8", protocol = "Balancer Vault", category = "FlashLoan", score_modifier = -0.4 },
    { address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", protocol = "Aave V3 Pool", category = "Lending", score_modifier = -0.35 },
    { address = "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", protocol = "Uniswap SwapRouter02", category = "DEX", score_modifier = -0.3 },
]
```

---

## [NEEDS CLARIFICATION]

- [ ] ProfitFlow의 `is_circular` 판정 기준: sender == receiver만 볼 것인지, 다중 hop도 추적할 것인지
- [ ] HistoricalLabel 데이터를 JSONL 파일로 관리할 것인지, Rust 코드 내 상수로 관리할 것인지
