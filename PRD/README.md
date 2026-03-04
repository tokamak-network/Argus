# Argus Sentinel 오탐률 개선 -- 디자인 문서

> Show Me The PRD로 생성됨 (2026-03-05)

## 배경

Argus Sentinel의 메인넷 운영 결과, 25건 알림 중 20건이 false positive (precision 20%).
Balancer Vault 정상 flash loan 차익거래가 Critical로 분류되는 것이 주원인.
이 프로젝트는 precision 70%+를 달성하여 외부 공유 가능한 수준으로 개선한다.

## 문서 구성

| 문서 | 내용 | 언제 읽나 |
|------|------|----------|
| [01_PRD.md](./01_PRD.md) | 뭘 만드는지, 왜 만드는지, 성공 기준 | 프로젝트 시작 전 |
| [02_DATA_MODEL.md](./02_DATA_MODEL.md) | 데이터 구조 (WhitelistConfig, AttackStage, ProfitFlow 등) | 타입 설계할 때 |
| [03_PHASES.md](./03_PHASES.md) | 3단계 계획 (화이트리스트 → 다단계 매핑 → 백테스트) | 개발 순서 정할 때 |
| [04_PROJECT_SPEC.md](./04_PROJECT_SPEC.md) | AI 규칙, 절대 하지 마 목록, 테스트/배포 가이드 | AI에게 코드 시킬 때마다 |

## 다음 단계

Phase 1을 시작하려면 [03_PHASES.md](./03_PHASES.md)의 "Phase 1 시작 프롬프트"를 복사하여 사용하세요.

## 미결 사항 종합

- [ ] 초기 화이트리스트에 포함할 프로토콜 목록 확정
- [ ] score_modifier 값 결정 (-0.3 vs -0.5 vs 차등)
- [ ] ProfitFlow is_circular 판정 기준 (1-hop vs multi-hop)
- [ ] HistoricalLabel 데이터 형식 (JSONL vs Rust 상수)
- [ ] 화이트리스트 로드 시점 (시작 시 1회 vs 주기적)
- [ ] 새 SuspicionReason의 기본 AttackStage

## 참고 자료

- [Forta Attack Detector](https://docs.forta.network/en/latest/attack-detector-bot/) — 다단계 공격 매핑 참조
- [BlockSec Phalcon](https://blocksec.com/blog/what-is-the-best-de-fi-hack-detection-and-prevention-system) — FP rate < 0.001%
- [HOUSTON (NDSS)](https://www.ndss-symposium.org/ndss-paper/houston-real-time-anomaly-detection-of-attacks-against-ethereum-defi-protocols/) — Cross-contract anomaly detection
