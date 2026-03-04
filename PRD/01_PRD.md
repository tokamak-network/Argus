# Argus Sentinel 오탐률 개선 -- PRD (Product Requirements Document)

> 생성일: 2026-03-05
> 생성 도구: Show Me The PRD

---

## 1. 제품 개요

### 한 줄 요약
Argus Sentinel의 오탐률을 80%에서 30% 이하로 낮춰, 보안 도구로서 외부 공유 가능한 수준의 precision(70%+)을 달성한다.

### 해결하는 문제
현재 Argus Sentinel은 메인넷에서 25건의 알림 중 20건이 false positive(Balancer Vault의 정상 flash loan 차익거래). precision 20%로는 보안 도구로서 신뢰도가 없어 어디에도 공유할 수 없다. "flash loan을 사용했다"는 사실만으로 Critical을 부여하는 단순 휴리스틱이 원인.

### 핵심 가치
- **높은 정밀도**: precision 70%+ (업계 기준 Forta Attack Detector와 유사한 수준)
- **DeFi 문맥 이해**: 정상 DeFi 활동(arb, batch swap)과 실제 공격을 구분
- **검증 가능한 성능**: Historical labeling으로 precision/recall 수치를 제시

### 경쟁 참조
| 도구 | 접근 방식 | 참고 |
|------|----------|------|
| [Forta Attack Detector](https://docs.forta.network/en/latest/attack-detector-bot/) | 4단계 공격 매핑 (Funding→Exploitation→Drain) | 다단계 검증으로 high precision |
| [BlockSec Phalcon](https://blocksec.com/blog/what-is-the-best-de-fi-hack-detection-and-prevention-system) | AI + DeFi semantics, FP rate < 0.001% | Custom trigger rules |
| [HOUSTON (NDSS 2025)](https://www.ndss-symposium.org/ndss-paper/houston-real-time-anomaly-detection-of-attacks-against-ethereum-defi-protocols/) | Cross-contract data flow 기반 이상 탐지 | 학술적 접근, real-time |

---

## 2. 사용자

### 주요 사용자
- **누구**: Argus Sentinel 운영자 (블록체인 보안 연구자, DeFi 프로토콜 팀)
- **상황**: 메인넷 실시간 모니터링 중 알림을 확인할 때
- **목표**: Critical 알림이 실제 공격인지 신뢰하고, 즉각 대응 판단을 내리고 싶다

### 사용자 시나리오
1. 보안 운영자가 Sentinel 대시보드에서 Critical 알림을 확인한다
2. 알림의 공격 단계(Funding→Exploitation→Drain)와 profit flow를 본다
3. 실제 공격으로 판단하고 해당 프로토콜에 경고를 발행한다

---

## 3. 핵심 기능

| 기능 | 설명 | 우선순위 | 복잡도 |
|------|------|----------|--------|
| DeFi 화이트리스트 엔진 | TOML에 등록된 DeFi 프로토콜 주소 매칭 시 score 감점 | P1 (Phase 1) | 간단 |
| 다단계 공격 매핑 | 각 SuspicionReason을 4단계(Funding/Preparation/Exploitation/Drain)에 매핑, 2단계+ 확인 시 Critical | P1 (Phase 2) | 보통 |
| Profit Extraction 탐지 | fund_flow에서 circular(정상 arb) vs drain(공격) 패턴 구분 | P1 (Phase 2) | 보통 |
| Historical Labeling 검증 | 알려진 해킹 TX + 정상 TX fixtures로 precision/recall 자동 측정 | P1 (Phase 3) | 보통 |

---

## 4. 탐지 파이프라인 흐름 (변경 후)

### 핵심 흐름
```
TX 수신 → Pre-Filter → 화이트리스트 체크 → 다단계 매핑 → Profit 분석 → Score 재계산 → Alert 발행
```

### 상세 흐름
1. **Pre-Filter (기존)**: receipt 기반 휴리스틱 (flash loan, ERC20 전송, gas 패턴)
2. **화이트리스트 체크 (신규)**: TOML에 등록된 DeFi 주소와 매칭 → score_modifier 적용
3. **다단계 매핑 (신규)**: 각 suspicion_reason을 AttackStage에 매핑, 확인된 단계 수로 priority 재계산
4. **Profit 분석 (신규)**: fund_flow에서 자금 순환 패턴 분석 → circular(arb)이면 감점, drain이면 가점
5. **Score 재계산**: 화이트리스트 감점 + 단계 수 + profit 분석 → 최종 suspicion_score
6. **Alert 발행**: threshold(0.85) 이상만 Critical로 발행

---

## 5. 성공 기준

- [ ] Precision 70% 이상 (True Positive / (True Positive + False Positive))
- [ ] Recall 60% 이상 (알려진 공격 TX의 60%+ 탐지)
- [ ] 기존 Balancer Vault arb TX 20건이 Critical에서 제외됨
- [ ] 알려진 해킹 TX (Euler, Curve 등) 10건 중 6건+ 탐지
- [ ] 모든 변경이 기존 397 테스트를 깨뜨리지 않음
- [ ] ECS 재배포 후 24시간 안정 운영

---

## 6. 안 만드는 것 (Out of Scope)

> 이 목록에 있는 건 이번 프로젝트에서 만들지 않습니다.

- **ML 기반 분류기** -- 이유: 레이블 데이터 부족 (70건 미만). rule-based 먼저 정립 후 ML 진입
- **외부 API 연동 (DeFiLlama 등)** -- 이유: 네트워크 의존성 추가 없이 TOML 정적 설정으로 충분
- **실시간 price oracle 연동** -- 이유: 복잡도 대비 precision 개선 효과 불확실
- **대시보드 UI 변경** -- 이유: 백엔드 탐지 로직만 변경. 대시보드는 기존 그대로 동작
- **Mempool 분석 고도화** -- 이유: RPC 모드에서는 mempool 접근 불가

---

## 7. [NEEDS CLARIFICATION]

> 아직 결정되지 않은 사항. 개발 전에 정해야 합니다.

- [ ] Balancer Vault 외에 초기 화이트리스트에 포함할 프로토콜 목록 (Aave V3, Uniswap V3, Curve, Compound?)
- [ ] score_modifier 값 결정: -0.3 (소폭 감점) vs -0.5 (강한 감점) vs 프로토콜별 차등
- [ ] Historical labeling용 "정상 TX" 데이터셋 수집 범위 (최근 7일? 30일?)
