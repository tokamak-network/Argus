//! WebSocket alert broadcaster for the Sentinel system.
//!
//! Provides a publish-subscribe layer that bridges the [`AlertHandler`] pipeline
//! with WebSocket clients. Each connected client receives a copy of every alert
//! as a JSON string over an `mpsc` channel.
//!
//! ```text
//!   SentinelAlert
//!     -> WsAlertHandler (implements AlertHandler)
//!       -> WsAlertBroadcaster
//!         -> subscriber_1 (mpsc::Receiver<String>)
//!         -> subscriber_2 (mpsc::Receiver<String>)
//!         -> ...
//! ```

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;

use super::service::AlertHandler;
use super::types::SentinelAlert;

/// Broadcaster that fans out serialized alert JSON to all subscribed clients.
///
/// Thread-safe: multiple threads can call [`subscribe`] and [`broadcast`]
/// concurrently. Disconnected subscribers (whose receiver has been dropped)
/// are pruned automatically on each broadcast.
pub struct WsAlertBroadcaster {
    subscribers: Mutex<Vec<mpsc::Sender<String>>>,
}

impl WsAlertBroadcaster {
    /// Create a new broadcaster with no subscribers.
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Register a new subscriber and return the receiving end of its channel.
    ///
    /// The returned `Receiver<String>` will receive JSON-serialized alerts
    /// for every subsequent `broadcast` call. Drop the receiver to unsubscribe.
    pub fn subscribe(&self) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel();
        let mut subs = match self.subscribers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        subs.push(tx);
        rx
    }

    /// Broadcast a serialized alert to all connected subscribers.
    ///
    /// Subscribers whose channel is disconnected (receiver dropped) are removed.
    pub fn broadcast(&self, alert: &SentinelAlert) {
        let json = match serde_json::to_string(alert) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[SENTINEL WS] Failed to serialize alert: {}", e);
                return;
            }
        };

        let mut subs = match self.subscribers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        // Retain only subscribers whose channel is still connected
        subs.retain(|tx| tx.send(json.clone()).is_ok());
    }

    /// Returns the current number of connected subscribers.
    #[cfg(test)]
    pub fn subscriber_count(&self) -> usize {
        let subs = match self.subscribers.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        subs.len()
    }
}

impl Default for WsAlertBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

/// Alert handler that forwards alerts to a [`WsAlertBroadcaster`].
///
/// Wraps a shared broadcaster so it can be plugged into the existing
/// alert pipeline (e.g. inside an `AlertDispatcher`).
pub struct WsAlertHandler {
    broadcaster: Arc<WsAlertBroadcaster>,
}

impl WsAlertHandler {
    /// Create a handler backed by the given broadcaster.
    pub fn new(broadcaster: Arc<WsAlertBroadcaster>) -> Self {
        Self { broadcaster }
    }

    /// Returns a reference to the underlying broadcaster.
    ///
    /// Callers can use this to register new WebSocket clients via [`WsAlertBroadcaster::subscribe`].
    pub fn broadcaster(&self) -> &Arc<WsAlertBroadcaster> {
        &self.broadcaster
    }
}

impl AlertHandler for WsAlertHandler {
    fn on_alert(&self, alert: SentinelAlert) {
        self.broadcaster.broadcast(&alert);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethrex_common::{H256, U256};

    fn make_alert(block_number: u64, tx_hash_byte: u8) -> SentinelAlert {
        let mut hash_bytes = [0u8; 32];
        hash_bytes[0] = tx_hash_byte;
        SentinelAlert {
            block_number,
            block_hash: H256::zero(),
            tx_hash: H256::from(hash_bytes),
            tx_index: 0,
            alert_priority: super::super::types::AlertPriority::High,
            suspicion_reasons: vec![],
            suspicion_score: 0.7,
            #[cfg(feature = "autopsy")]
            detected_patterns: vec![],
            #[cfg(feature = "autopsy")]
            fund_flows: vec![],
            total_value_at_risk: U256::zero(),
            summary: "test ws alert".to_string(),
            total_steps: 100,
            feature_vector: None,
        }
    }

    #[test]
    fn ws_broadcaster_subscribe_and_receive() {
        let broadcaster = WsAlertBroadcaster::new();
        let rx = broadcaster.subscribe();

        let alert = make_alert(42, 0xAA);
        broadcaster.broadcast(&alert);

        let msg = rx.recv().expect("should receive message");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 42);
    }

    #[test]
    fn ws_broadcaster_multiple_subscribers_receive_same_alert() {
        let broadcaster = WsAlertBroadcaster::new();
        let rx1 = broadcaster.subscribe();
        let rx2 = broadcaster.subscribe();
        let rx3 = broadcaster.subscribe();

        let alert = make_alert(100, 0xBB);
        broadcaster.broadcast(&alert);

        let msg1 = rx1.recv().expect("subscriber 1 should receive");
        let msg2 = rx2.recv().expect("subscriber 2 should receive");
        let msg3 = rx3.recv().expect("subscriber 3 should receive");

        // All subscribers get identical JSON
        assert_eq!(msg1, msg2);
        assert_eq!(msg2, msg3);

        let parsed: serde_json::Value = serde_json::from_str(&msg1).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 100);
    }

    #[test]
    fn ws_broadcaster_disconnected_subscriber_cleanup() {
        let broadcaster = WsAlertBroadcaster::new();

        let rx1 = broadcaster.subscribe();
        let rx2 = broadcaster.subscribe();
        assert_eq!(broadcaster.subscriber_count(), 2);

        // Drop rx1 — its sender should be pruned on next broadcast
        drop(rx1);

        let alert = make_alert(50, 0xCC);
        broadcaster.broadcast(&alert);

        // After broadcast, only rx2's sender remains
        assert_eq!(broadcaster.subscriber_count(), 1);

        let msg = rx2.recv().expect("subscriber 2 should still receive");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 50);
    }

    #[test]
    fn ws_alert_handler_implements_alert_handler() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let rx = broadcaster.subscribe();
        let handler = WsAlertHandler::new(broadcaster.clone());

        // Use through the AlertHandler trait
        let handler_ref: &dyn AlertHandler = &handler;
        handler_ref.on_alert(make_alert(77, 0xDD));

        let msg = rx.recv().expect("should receive via AlertHandler");
        let parsed: serde_json::Value = serde_json::from_str(&msg).expect("should be valid JSON");
        assert_eq!(parsed["block_number"], 77);
        assert_eq!(parsed["summary"], "test ws alert");
    }

    #[test]
    fn ws_broadcaster_empty_broadcast_does_not_panic() {
        let broadcaster = WsAlertBroadcaster::new();
        assert_eq!(broadcaster.subscriber_count(), 0);

        // Broadcasting with no subscribers should be a no-op
        broadcaster.broadcast(&make_alert(1, 0xEE));

        // Still zero subscribers
        assert_eq!(broadcaster.subscriber_count(), 0);
    }

    #[test]
    fn ws_broadcaster_sequential_broadcasts() {
        let broadcaster = WsAlertBroadcaster::new();
        let rx = broadcaster.subscribe();

        broadcaster.broadcast(&make_alert(1, 0x01));
        broadcaster.broadcast(&make_alert(2, 0x02));
        broadcaster.broadcast(&make_alert(3, 0x03));

        let msg1: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let msg2: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();
        let msg3: serde_json::Value = serde_json::from_str(&rx.recv().unwrap()).unwrap();

        assert_eq!(msg1["block_number"], 1);
        assert_eq!(msg2["block_number"], 2);
        assert_eq!(msg3["block_number"], 3);
    }

    #[test]
    fn ws_alert_handler_broadcaster_accessor() {
        let broadcaster = Arc::new(WsAlertBroadcaster::new());
        let handler = WsAlertHandler::new(broadcaster.clone());

        // Subscribe via the accessor
        let rx = handler.broadcaster().subscribe();
        handler.on_alert(make_alert(99, 0xFF));

        let msg = rx
            .recv()
            .expect("should receive via accessor-registered sub");
        assert!(msg.contains("99"));
    }
}
