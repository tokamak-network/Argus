//! Phase 0 PoC integration tests — LLM accuracy measurement.
//!
//! These tests call the API via LiteLLM proxy and are `#[ignore]` by default.
//! Run with: `LITELLM_API_KEY=sk-... cargo test --features ai_agent poc_test -- --ignored`
//!
//! Environment variables:
//! - `LITELLM_API_KEY` — required
//! - `LITELLM_BASE_URL` — optional (default: `https://api.ai.tokamak.network`)
//!
//! Success criteria (PRD): 80%+ accuracy on 13 fixtures (3 attack + 10 normal).

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::sentinel::ai::client::{AiClient, LiteLLMClient};
    use crate::sentinel::ai::fixtures::load_agent_context_from_file;
    use crate::sentinel::ai::prompts::SYSTEM_PROMPT;

    /// Screening model (fast, cheap) on LiteLLM proxy.
    const MODEL: &str = "gemini-3-flash";
    /// Deep analysis model (stronger reasoning) on LiteLLM proxy.
    const DEEP_MODEL: &str = "gemini-3-pro";

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ai")
    }

    /// Parse the `_meta.attack_type` field from fixture JSON to determine ground truth.
    fn is_attack_fixture(filename: &str) -> bool {
        filename.starts_with("attack_")
    }

    // ── Individual fixture tests ─────────────────────────────────────────────

    #[tokio::test]
    #[ignore]
    async fn poc_attack_reentrancy_dao() {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let ctx = load_agent_context_from_file(&fixtures_dir().join("attack_reentrancy_dao.json"))
            .unwrap();
        let resp = client.judge(&ctx, MODEL).await.unwrap();
        eprintln!(
            "reentrancy_dao: is_attack={}, confidence={:.2}, type={:?}, cost=${:.6}",
            resp.verdict.is_attack,
            resp.verdict.confidence,
            resp.verdict.attack_type,
            resp.usage.cost_usd(MODEL),
        );
        assert!(
            resp.verdict.is_attack,
            "Expected attack, got benign. Reasoning: {}",
            resp.verdict.reasoning
        );
    }

    #[tokio::test]
    #[ignore]
    async fn poc_attack_flash_loan_euler() {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let ctx =
            load_agent_context_from_file(&fixtures_dir().join("attack_flash_loan_euler.json"))
                .unwrap();
        let resp = client.judge(&ctx, MODEL).await.unwrap();
        eprintln!(
            "flash_loan_euler: is_attack={}, confidence={:.2}, type={:?}, cost=${:.6}",
            resp.verdict.is_attack,
            resp.verdict.confidence,
            resp.verdict.attack_type,
            resp.usage.cost_usd(MODEL),
        );
        assert!(
            resp.verdict.is_attack,
            "Expected attack, got benign. Reasoning: {}",
            resp.verdict.reasoning
        );
    }

    #[tokio::test]
    #[ignore]
    async fn poc_attack_price_manipulation_balancer() {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let ctx = load_agent_context_from_file(
            &fixtures_dir().join("attack_price_manipulation_balancer.json"),
        )
        .unwrap();
        let resp = client.judge(&ctx, MODEL).await.unwrap();
        eprintln!(
            "price_manipulation_balancer: is_attack={}, confidence={:.2}, type={:?}, cost=${:.6}",
            resp.verdict.is_attack,
            resp.verdict.confidence,
            resp.verdict.attack_type,
            resp.usage.cost_usd(MODEL),
        );
        assert!(
            resp.verdict.is_attack,
            "Expected attack, got benign. Reasoning: {}",
            resp.verdict.reasoning
        );
    }

    #[tokio::test]
    #[ignore]
    async fn poc_normal_eth_transfer_simple() {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let ctx =
            load_agent_context_from_file(&fixtures_dir().join("normal_eth_transfer_simple.json"))
                .unwrap();
        let resp = client.judge(&ctx, MODEL).await.unwrap();
        eprintln!(
            "eth_transfer_simple: is_attack={}, confidence={:.2}, cost=${:.6}",
            resp.verdict.is_attack,
            resp.verdict.confidence,
            resp.usage.cost_usd(MODEL),
        );
        assert!(
            !resp.verdict.is_attack,
            "Expected benign, got attack. Reasoning: {}",
            resp.verdict.reasoning
        );
    }

    #[tokio::test]
    #[ignore]
    async fn poc_normal_defi_swap_uniswap() {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let ctx =
            load_agent_context_from_file(&fixtures_dir().join("normal_defi_swap_uniswap.json"))
                .unwrap();
        let resp = client.judge(&ctx, MODEL).await.unwrap();
        eprintln!(
            "defi_swap_uniswap: is_attack={}, confidence={:.2}, cost=${:.6}",
            resp.verdict.is_attack,
            resp.verdict.confidence,
            resp.usage.cost_usd(MODEL),
        );
        assert!(
            !resp.verdict.is_attack,
            "Expected benign, got attack. Reasoning: {}",
            resp.verdict.reasoning
        );
    }

    // ── Full batch test (all 13 fixtures) ────────────────────────────────────

    async fn run_accuracy_batch(model: &str) {
        let client = LiteLLMClient::from_env(SYSTEM_PROMPT.to_string()).unwrap();
        let dir = fixtures_dir();

        let mut fixtures: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        fixtures.sort();

        let mut correct = 0u32;
        let mut total = 0u32;
        let mut total_cost = 0.0f64;
        let mut total_input_tokens = 0u32;
        let mut total_output_tokens = 0u32;
        let mut results: Vec<String> = Vec::new();

        for filename in &fixtures {
            let ctx = load_agent_context_from_file(&dir.join(filename)).unwrap();
            let expected_attack = is_attack_fixture(filename);

            let resp = client.judge(&ctx, model).await.unwrap();
            let cost = resp.usage.cost_usd(model);
            total_cost += cost;
            total_input_tokens += resp.usage.input_tokens;
            total_output_tokens += resp.usage.output_tokens;

            let is_correct = resp.verdict.is_attack == expected_attack;
            if is_correct {
                correct += 1;
            }
            total += 1;

            let status = if is_correct { "OK" } else { "MISS" };
            let result_line = format!(
                "[{status}] {filename}: expected={expected_attack}, got={}, conf={:.2}, type={:?}, cost=${cost:.6}",
                resp.verdict.is_attack, resp.verdict.confidence, resp.verdict.attack_type,
            );
            eprintln!("{result_line}");
            results.push(result_line);
        }

        let accuracy = if total > 0 {
            f64::from(correct) / f64::from(total) * 100.0
        } else {
            0.0
        };

        eprintln!("\n=== PoC Results (Model: {model}) ===");
        eprintln!("Accuracy: {correct}/{total} ({accuracy:.1}%)");
        eprintln!("Total cost: ${total_cost:.6}");
        eprintln!("Total tokens: {total_input_tokens} input + {total_output_tokens} output");
        eprintln!(
            "Avg cost per request: ${:.6}",
            total_cost / f64::from(total)
        );

        assert!(
            accuracy >= 80.0,
            "Accuracy {accuracy:.1}% below 80% threshold. Results:\n{}",
            results.join("\n")
        );
    }

    #[tokio::test]
    #[ignore]
    async fn poc_full_accuracy_batch() {
        run_accuracy_batch(MODEL).await;
    }

    /// Same batch test but with gemini-3-pro (deep analysis model).
    #[tokio::test]
    #[ignore]
    async fn poc_full_accuracy_batch_deep_model() {
        run_accuracy_batch(DEEP_MODEL).await;
    }
}
