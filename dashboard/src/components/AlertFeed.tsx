import { useState, useEffect, useRef, useCallback } from "react";
import type { SentinelAlert, WsConnectionStatus } from "@/types/sentinel";
import { AlertCard } from "./AlertCard";

const MAX_ALERTS = 50;
const MAX_BACKOFF_MS = 30_000;
const INITIAL_BACKOFF_MS = 1_000;

interface Props {
  readonly wsUrl?: string;
}

function ConnectionDot({ status }: { readonly status: WsConnectionStatus }) {
  const color: Record<WsConnectionStatus, string> = {
    connected: "bg-tokamak-green",
    disconnected: "bg-tokamak-red",
    reconnecting: "bg-tokamak-yellow",
  };
  const label: Record<WsConnectionStatus, string> = {
    connected: "Connected",
    disconnected: "Disconnected",
    reconnecting: "Reconnecting...",
  };

  return (
    <div className="flex items-center gap-2 text-xs text-slate-400">
      <span className={`inline-block h-2 w-2 rounded-full ${color[status]}`} />
      {label[status]}
    </div>
  );
}

export function useWsReconnect(
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

export function AlertFeed({ wsUrl }: Props) {
  const [alerts, setAlerts] = useState<readonly SentinelAlert[]>([]);
  const [status, setStatus] = useState<WsConnectionStatus>("disconnected");

  const resolvedUrl = wsUrl ?? defaultWsUrl();

  const handleMessage = useCallback((alert: SentinelAlert) => {
    setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
  }, []);

  const handleStatus = useCallback((s: WsConnectionStatus) => {
    setStatus(s);
  }, []);

  useWsReconnect(resolvedUrl, handleMessage, handleStatus);

  return (
    <section>
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Live Alert Feed</h2>
        <ConnectionDot status={status} />
      </div>

      {alerts.length === 0 ? (
        <p className="text-sm text-slate-500">Waiting for alerts...</p>
      ) : (
        <div className="flex flex-col gap-3">
          {alerts.map((alert, i) => (
            <AlertCard key={`${alert.tx_hash}-${i}`} alert={alert} />
          ))}
        </div>
      )}
    </section>
  );
}

function defaultWsUrl(): string {
  if (typeof window === "undefined") return "ws://localhost:8545/sentinel/ws";
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/sentinel/ws`;
}
