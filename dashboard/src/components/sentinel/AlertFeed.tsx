import { useState, useEffect, useRef, useCallback } from "react";
import type { SentinelAlert, WsConnectionStatus } from "@/types/sentinel";
import { AlertCard } from "./AlertCard";

const MAX_ALERTS = 50;
const MAX_BACKOFF_MS = 30_000;
const INITIAL_BACKOFF_MS = 1_000;

interface Props {
  readonly wsUrl?: string;
}

function useWsReconnect(
  wsUrl: string,
  onMessage: (alert: SentinelAlert) => void,
  onStatusChange: (status: WsConnectionStatus) => void,
) {
  const backoffRef = useRef(INITIAL_BACKOFF_MS);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!mountedRef.current) return;

    onStatusChange("reconnecting");
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      backoffRef.current = INITIAL_BACKOFF_MS;
      onStatusChange("connected");
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const alert: SentinelAlert = JSON.parse(String(event.data));
        onMessage(alert);
      } catch {
        // Ignore malformed messages
      }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      onStatusChange("disconnected");
      const delay = backoffRef.current;
      backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS);
      timerRef.current = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [wsUrl, onMessage, onStatusChange]);

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (timerRef.current !== null) clearTimeout(timerRef.current);
      wsRef.current?.close();
    };
  }, [connect]);
}

function defaultWsUrl(): string {
  if (typeof window === "undefined") return "ws://localhost:8545/sentinel/ws";
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/sentinel/ws`;
}

export function AlertFeed({ wsUrl }: Props) {
  const [alerts, setAlerts] = useState<readonly SentinelAlert[]>([]);
  const [status, setStatus] = useState<WsConnectionStatus>("disconnected");
  const [filter, setFilter] = useState<"all" | "critical">("all");

  const resolvedUrl = wsUrl ?? defaultWsUrl();

  const handleMessage = useCallback((alert: SentinelAlert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
  }, []);

  const handleStatus = useCallback((s: WsConnectionStatus) => {
    setStatus(s);
  }, []);

  useWsReconnect(resolvedUrl, handleMessage, handleStatus);

  const filtered =
    filter === "critical"
      ? alerts.filter((a) => a.alert_priority === "Critical")
      : alerts;

  return (
    <section className="space-y-4">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <span className="material-symbols-outlined text-sentinel-primary">sensors</span>
          Real-time Alert Feed
        </h2>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setFilter("all")}
            className={`px-3 py-1 text-xs rounded-full cursor-pointer transition-colors ${
              filter === "all"
                ? "bg-sentinel-border text-white"
                : "bg-sentinel-border/50 text-slate-400 hover:bg-sentinel-primary hover:text-white"
            }`}
          >
            All
          </button>
          <button
            type="button"
            onClick={() => setFilter("critical")}
            className={`px-3 py-1 text-xs rounded-full cursor-pointer transition-colors ${
              filter === "critical"
                ? "bg-sentinel-border text-white"
                : "bg-sentinel-border/50 text-slate-400 hover:bg-sentinel-primary hover:text-white"
            }`}
          >
            Critical Only
          </button>
        </div>
      </div>

      <div className="max-h-[500px] overflow-y-auto custom-scrollbar space-y-4 pr-2">
        {filtered.length === 0 ? (
          <p className="text-sm text-slate-500">Waiting for alerts...</p>
        ) : (
          filtered.map((alert, i) => (
            <div key={`${alert.tx_hash}-${i}`}>
              <AlertCard alert={alert} />
            </div>
          ))
        )}
      </div>
    </section>
  );
}
