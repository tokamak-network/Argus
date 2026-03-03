//! Webhook alert handler for HTTP POST notifications.
//!
//! Gated behind `autopsy` feature since it requires `reqwest`.

use std::time::Duration;

use super::service::AlertHandler;
use super::types::SentinelAlert;

/// Configuration for the webhook alert handler.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: Duration::from_secs(5),
            max_retries: 3,
            initial_backoff: Duration::from_secs(1),
        }
    }
}

/// Alert handler that POSTs serialized alerts to an HTTP endpoint.
///
/// On failure, retries with exponential backoff up to `max_retries` times.
/// Never panics — all errors are logged to stderr.
pub struct WebhookAlertHandler {
    config: WebhookConfig,
    client: reqwest::blocking::Client,
}

impl WebhookAlertHandler {
    pub fn new(config: WebhookConfig) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.timeout)
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self { config, client }
    }

    fn send_with_retries(&self, body: &str) {
        let mut backoff = self.config.initial_backoff;

        for attempt in 0..=self.config.max_retries {
            match self
                .client
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .body(body.to_owned())
                .send()
            {
                Ok(resp) if resp.status().is_success() => return,
                Ok(resp) => {
                    if attempt == self.config.max_retries {
                        eprintln!(
                            "[SENTINEL WEBHOOK] Failed after {} retries: HTTP {}",
                            self.config.max_retries,
                            resp.status()
                        );
                        return;
                    }
                    eprintln!(
                        "[SENTINEL WEBHOOK] Attempt {}/{}: HTTP {}, retrying in {:?}",
                        attempt + 1,
                        self.config.max_retries,
                        resp.status(),
                        backoff
                    );
                }
                Err(e) => {
                    if attempt == self.config.max_retries {
                        eprintln!(
                            "[SENTINEL WEBHOOK] Failed after {} retries: {}",
                            self.config.max_retries, e
                        );
                        return;
                    }
                    eprintln!(
                        "[SENTINEL WEBHOOK] Attempt {}/{}: {}, retrying in {:?}",
                        attempt + 1,
                        self.config.max_retries,
                        e,
                        backoff
                    );
                }
            }

            std::thread::sleep(backoff);
            backoff *= 2;
        }
    }
}

impl AlertHandler for WebhookAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        let body = match serde_json::to_string(&alert) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("[SENTINEL WEBHOOK] Failed to serialize alert: {}", e);
                return;
            }
        };

        self.send_with_retries(&body);
    }
}
