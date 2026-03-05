# Argus AI Agent — Data Model

## Entity Relationship

```
                  ┌──────────────┐
                  │ CostTracker  │
                  │              │
                  │ monthly_budget_usd │
                  │ daily_limit_usd    │
                  │ total_cost_usd     │
                  └──┬───────┬───┘
                     │       │
              check()│       │record()
                     ▼       │
┌─────────────────┐     ┌────┴────────────┐
│  AgentContext    │────▶│  AgentVerdict    │
│                 │     │                  │
│ tx_hash         │     │ is_attack        │
│ block_number    │     │ confidence       │
│ call_graph      │     │ attack_type      │
│ storage_mutations│    │ reasoning        │
│ erc20_transfers │     │ evidence         │
│ eth_transfers   │     │ false_positive_reason │
│ log_events      │     │ evidence_valid   │
│ delegatecalls   │     │ model_used       │
│ contract_creations│   │ tokens_used      │
│ revert_count    │     │ latency_ms       │
│ gas_used        │     └──────────────────┘
│ value_wei       │
│ suspicious_score│
└─────────────────┘

흐름: CostTracker.check() → AiClient.judge(AgentContext) → AgentVerdict → CostTracker.record()
```

## AgentContext

AI에게 전달되는 TX 분석 컨텍스트. opcode trace에서 추출한 구조화된 정보.

| Field | Type | Description |
|-------|------|-------------|
| tx_hash | H256 | 트랜잭션 해시 |
| block_number | u64 | 블록 번호 |
| from | Address | 송신자 |
| to | Option\<Address\> | 수신자 (contract creation이면 None) |
| value_wei | U256 | 전송 ETH 양 |
| gas_used | u64 | 사용된 가스 |
| succeeded | bool | TX 성공 여부 |
| revert_count | u32 | TX 내부 revert 횟수 (reentrancy guard 탐지 핵심) |
| suspicious_score | f64 | pre-filter 점수 |
| suspicion_reasons | Vec\<String\> | pre-filter 탐지 이유 |
| call_graph | Vec\<CallFrame\> | 호출 그래프 |
| storage_mutations | Vec\<StorageMutation\> | 스토리지 변경 |
| erc20_transfers | Vec\<TokenTransfer\> | ERC-20 전송 |
| eth_transfers | Vec\<EthTransfer\> | ETH 전송 |
| log_events | Vec\<LogEvent\> | Transfer 외 이벤트 (Approval, Swap, Sync 등) |
| delegatecalls | Vec\<DelegateCallInfo\> | DELEGATECALL 목록 |
| contract_creations | Vec\<ContractCreation\> | CREATE/CREATE2 |

### Sub-types

#### CallFrame
```rust
struct CallFrame {
    depth: u16,  // EVM 호출 깊이 제한 1024 — u8(255)로는 부족
    caller: Address,
    target: Address,
    value: U256,
    input_selector: Option<[u8; 4]>,  // 함수 시그니처 (4byte)
    input_size: usize,
    output_size: usize,
    gas_used: u64,
    call_type: CallType,  // CALL, STATICCALL, DELEGATECALL, CALLCODE
    reverted: bool,
}
```

#### StorageMutation
```rust
struct StorageMutation {
    contract: Address,
    slot: H256,
    old_value: H256,
    new_value: H256,
    in_callback: bool,  // reentrancy indicator
}
```

#### TokenTransfer
```rust
struct TokenTransfer {
    token: Address,
    from: Address,
    to: Address,
    amount: U256,
}
```

#### EthTransfer
```rust
struct EthTransfer {
    from: Address,
    to: Address,
    value: U256,
    call_depth: u16,
}
```

#### LogEvent
```rust
struct LogEvent {
    address: Address,
    topic0: H256,           // event signature
    topics: Vec<H256>,      // indexed params
    data_size: usize,       // non-indexed data size
}
```

#### DelegateCallInfo
```rust
struct DelegateCallInfo {
    caller: Address,
    target: Address,
    input_selector: Option<[u8; 4]>,  // fallback 함수나 빈 calldata도 가능 (프록시/업그레이드 패턴)
}
```

#### ContractCreation
```rust
struct ContractCreation {
    deployer: Address,
    deployed: Address,
    code_size: usize,
    create_type: CreateType,  // CREATE, CREATE2
}
```

## AgentVerdict

AI의 판단 결과.

| Field | Type | Description |
|-------|------|-------------|
| is_attack | bool | 공격 여부 |
| confidence | f64 | 확신도 (0.0 - 1.0) |
| attack_type | Option\<AttackType\> | 공격 유형 (아래 enum 참조) |
| reasoning | String | 판단 근거 (자연어) |
| evidence | Vec\<String\> | 핵심 증거 목록 |
| evidence_valid | bool | Hallucination Guard 검증 결과 |
| false_positive_reason | Option\<String\> | 오탐 판단 시 이유 |
| model_used | String | 사용된 모델 (haiku/sonnet) |
| tokens_used | u32 | 소비된 토큰 수 |
| latency_ms | u64 | 응답 시간 |

### AttackType enum

```rust
enum AttackType {
    Reentrancy,
    FlashLoan,
    PriceManipulation,
    AccessControl,
    FrontRunning,
    Sandwich,
    Other(String),  // 미분류 공격용
}
```

LLM 출력을 enum으로 제한하여 일관성을 보장한다. JSON 응답에서 문자열을 파싱하여 매핑하고, 매핑 실패 시 `Other(raw_string)`으로 수용한다.

### Hallucination Guard 검증 알고리즘

AI가 반환한 `evidence` 각 항목을 `AgentContext` 데이터와 대조 검증한다. 하나라도 실패하면 `evidence_valid = false`.

| 검증 항목 | 대조 대상 | 판정 기준 |
|----------|----------|----------|
| evidence에 언급된 주소 | `call_graph`, `erc20_transfers`, `eth_transfers`, `delegatecalls` | 해당 주소가 하나 이상의 필드에 존재 |
| evidence에 언급된 금액 | `erc20_transfers.amount`, `eth_transfers.value` | 실제 값 대비 ±10% 이내 (PoC에서 LLM 수치 오차 측정 후 확정. 10%는 초기 placeholder) |
| evidence에 언급된 함수 시그니처 | `call_graph[].input_selector` | 4byte 일치 |
| evidence에 언급된 이벤트 | `log_events[].topic0` | topic hash 일치 |
| evidence 항목 수 | — | 최소 1개 이상 (빈 evidence 거부) |

구현: [`04_PROJECT_SPEC.md § guard.rs`](./04_PROJECT_SPEC.md#project-structure)

## CostTracker

비용 관리 엔티티. 파일 기반 영속성.

> **f64 정밀도:** 화폐를 `f64`로 표현하면 누적 오차가 발생할 수 있으나, 월 $150 규모에서 30,000건 합산 시 오차는 ~$0.001 미만이다. 정수형(`u64` cents)보다 JSON 직렬화와 TOML 설정의 가독성을 우선했다. 비용 비교 시 epsilon(`0.01`) 허용치를 적용한다.

| Field | Type | Description |
|-------|------|-------------|
| monthly_budget_usd | f64 | 월 예산 상한 (default: 150.0). 비용 산출 근거: [01_PRD.md § 비용 추정](./01_PRD.md#비용-추정-근거) |
| daily_limit_usd | f64 | 일 예산 상한 (default: 10.0) |
| hourly_rate_limit | u32 | 시간당 최대 요청 수 (default: 100) |
| max_concurrent_per_block | u8 | 블록당 최대 동시 AI 요청 (default: 3) |
| total_cost_usd | f64 | 이번 달 누적 비용 |
| today_cost_usd | f64 | 오늘 누적 비용 |
| total_tokens | u64 | 이번 달 총 토큰 |
| request_count | u32 | 이번 달 총 요청 수 |
| haiku_requests | u32 | Haiku 요청 수 |
| sonnet_requests | u32 | Sonnet 요청 수 |
| last_daily_reset | String | 마지막 일별 리셋 날짜 |
| last_monthly_reset | String | 마지막 월별 리셋 날짜 |
| budget_exhausted | bool | 예산 소진 여부 |
