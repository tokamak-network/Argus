/** Alert priority levels matching the Rust `AlertPriority` enum. */
export type AlertPriority = "Medium" | "High" | "Critical";

/** Reason a transaction was flagged by the pre-filter. */
export interface SuspicionReason {
  readonly type: string;
  readonly details?: Record<string, unknown>;
}

/** Alert emitted by the Sentinel deep analysis engine. */
export interface SentinelAlert {
  readonly block_number: number;
  readonly block_hash: string;
  readonly tx_hash: string;
  readonly tx_index: number;
  readonly alert_priority: AlertPriority;
  readonly suspicion_reasons: readonly SuspicionReason[];
  readonly suspicion_score: number;
  readonly total_value_at_risk: string;
  readonly summary: string;
  readonly total_steps: number;
}

/** Query parameters for the history API. */
export interface AlertQueryParams {
  readonly page: number;
  readonly page_size: number;
  readonly priority?: AlertPriority;
  readonly block_from?: number;
  readonly block_to?: number;
  readonly pattern_type?: string;
}

/** Paginated result from the history API. */
export interface AlertQueryResult {
  readonly alerts: readonly SentinelAlert[];
  readonly total: number;
  readonly page: number;
  readonly page_size: number;
}

/** Metrics snapshot from the `/sentinel/metrics` endpoint. */
export interface SentinelMetricsSnapshot {
  readonly blocks_scanned: number;
  readonly txs_scanned: number;
  readonly txs_flagged: number;
  readonly alerts_emitted: number;
}

/** Connection status for the WebSocket feed. */
export type WsConnectionStatus = "connected" | "disconnected" | "reconnecting";
