# Argus Handoff

## 프로젝트 개요

Argus는 tokamak-network/ethrex의 tokamak-debugger 크레이트를 독립 레포로 분리한 프로젝트.
Ethereum 실시간 공격 탐지 + 사후 포렌식 + 타임트래블 디버거.

- **레포**: https://github.com/tokamak-network/Argus
- **목적**: GitHub 스타 획득 → Tokamak Network 개발 역량 증명
- **배경**: ethrex 포크에서는 main에 코드가 0줄 (LambdaClass upstream만 존재), 성과 귀속 불가 → 독립 레포로 분리

## 현재 상태 (2026-03-03)

### 완료

- [x] ethrex tokamak-debugger 코드 → Argus 레포로 이동 (105파일, 30,472 LoC)
- [x] Cargo.toml: git dep으로 ethrex LEVM 참조 (`rev = "03fc1858"`)
- [x] 크레이트명 `tokamak_debugger` → `argus` 리네이밍 완료
- [x] `cargo check` / `cargo test` (283 passed) / `cargo fmt` / `cargo clippy` 전부 통과
- [x] GitHub Actions CI (check, test, clippy, fmt)
- [x] Dockerfile (multi-stage build)
- [x] README: CI 배지, 데모 출력, 경쟁 비교표, 아키텍처 다이어그램
- [x] GitHub topics 9개 설정 (ethereum, security, attack-detection, evm, rust 등)
- [x] Case Study: Balancer V2 $128M Exploit 분석 (`docs/analysis-balancer-v2-exploit.md`)
- [x] 듀얼 라이센스 (MIT / Apache 2.0)

### 미완료 (우선순위 순)

- [ ] **데모 GIF 녹화** → README에 삽입 (시각적 임팩트, 스타 전환율 핵심)
- [ ] **awesome-ethereum-security PR** 제출 (https://github.com/crytic/awesome-ethereum-security)
- [ ] **유통**: Balancer 분석 콘텐츠를 Twitter/Reddit/HN에 게시
- [ ] **추가 Case Study**: Bybit $1.4B (supply chain), Unleash $3.9M 등
- [ ] **Docker Hub 이미지** 퍼블리시 (`docker run tokamak/argus-demo`)
- [ ] **CLAUDE.md** 작성 (개발 가이드, 빌드 명령어, 아키텍처 설명)
- [ ] ethrex upstream 변경 시 git dep rev 업데이트 전략

## 기술 구조

```
Argus (독립 레포)
  │
  ├── src/sentinel/    (8,731 LoC) — 실시간 탐지 파이프라인
  ├── src/autopsy/     (3,544 LoC) — 포렌식 분석
  ├── src/engine.rs    — 타임트래블 디버거 코어
  ├── src/recorder.rs  — opcode 레코더
  ├── examples/        — 3개 데모 (sentinel, autopsy, dashboard)
  ├── dashboard/       — Astro + React 웹 UI
  │
  └── [git dep] ethrex LEVM (rev: 03fc1858)
      └── ethrex-common, ethrex-storage, ethrex-blockchain, ethrex-vm
```

## 핵심 의사결정 기록

1. **왜 독립 레포?**: ethrex 포크의 main에 본인 코드 0줄. Contributors 페이지에 이름 없음. 스타를 받아도 LambdaClass 성과로 보임.
2. **왜 git dep?**: 전면 코드 추출은 4~6주. git dep은 Cargo.toml만 설정하면 됨. 빌드 시 ethrex LEVM을 자동으로 가져옴.
3. **rev 고정**: `branch` 대신 `rev = "03fc1858"`로 고정. ethrex upstream 변경에 영향 안 받음.
4. **edition 2024**: ethrex가 edition 2024 사용. Rust 1.85+ 필요.

## 빌드 명령어

```bash
cargo check                          # 빌드 확인
cargo test                           # 283 테스트 실행
cargo run --example sentinel_realtime_demo  # Sentinel 데모
cargo run --example reentrancy_demo         # Autopsy 데모
cargo clippy --all-features          # lint
cargo fmt --check                    # 포맷 확인
```

## 유통 전략 메모

- **HN 제목안**: "Show HN: Real-time attack detection for Ethereum — would have caught the $128M Balancer exploit"
- **Reddit 대상**: r/ethereum, r/ethdev, r/defi
- **Twitter**: 보안 연구자 태깅 (samczsun, pcaversaccio, BlockSec 등)
- **awesome-list**: crytic/awesome-ethereum-security에 "Runtime Monitoring" 카테고리로 PR
- **타이밍**: 대형 해킹 발생 직후가 최적의 유통 시점
