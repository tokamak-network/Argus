# Argus AI Agent — PRD Navigation

> **독자:** Argus 핵심 개발자 (Rust + EVM 배경 필요)
>
> **문체 규칙:** 01/03은 서술체("~한다"), 02는 정의체(명사형), 04는 명령체("~하라"). 표 내부는 간결성을 위해 명사형 허용.

## Documents

| # | Document | Description |
|---|----------|-------------|
| 1 | [01_PRD.md](./01_PRD.md) | Product Requirements Document — 왜, 무엇을, 어떻게 |
| 2 | [02_DATA_MODEL.md](./02_DATA_MODEL.md) | Data Model — AgentContext, AgentVerdict, CostTracker |
| 3 | [03_PHASES.md](./03_PHASES.md) | Phase Plan — Phase 0 (PoC) + 3단계 구현 계획 |
| 4 | [04_PROJECT_SPEC.md](./04_PROJECT_SPEC.md) | Project Spec — 기술 스택, 규칙, 테스트, 배포 |

## Decision Summary

| 결정 항목 | 선택 |
|----------|------|
| 운영 범위 | 실시간 (2-pass 비동기) + 사후분석 통합 |
| AI 입력 | AgentContext (opcode trace에서 추출한 구조화된 JSON) |
| 월 비용 | $150 이하 (prompt caching 적용) |
| MVP 범위 | 중간 (AI 판단 엔진 + 컨텍스트 추출기 + Autopsy AI + 비용 가드레일) |
| AI SDK | anthropic-sdk-rust (MVP) → LiteLLM 전환 가능 설계 |
| 모델 | Haiku 4.5 (스크리닝) + Sonnet 4.6 (심층) |
| API 키 | 환경변수 (ANTHROPIC_API_KEY) |
| Feature flag | `ai_agent` (언더스코어) |

## Blockers (Phase 1 착수 전 필수)

Phase 0 전제조건 및 PoC 작업 전체 목록은 [03_PHASES.md § Phase 0](./03_PHASES.md#phase-0-poc-검증-1-2-weeks) 참조.

핵심 블로커 요약:
- [ ] Phase 0 PoC 정확도 80% 이상
- [ ] `rpc_service.rs` 버그 수정 완료
- [ ] `anthropic-sdk-rust` 호환성 검증 (또는 대안 확인)

## Phase 0 필수 준비 (PoC와 병행)

- [ ] Phase 0: 공격 3 + 정상 10 = 13개로 PoC 검증 → Phase 1에서 공격 10 + 정상 10 = 20개+로 확장

## Nice-to-have (착수 후 가능)

- [ ] LiteLLM 프록시 배포 방식 결정 (사이드카 vs 별도 서비스)
- [ ] Haiku/Sonnet 프롬프트 초안 작성
- [ ] ECS Fargate 배포 시 Secrets Manager에 ANTHROPIC_API_KEY 추가
