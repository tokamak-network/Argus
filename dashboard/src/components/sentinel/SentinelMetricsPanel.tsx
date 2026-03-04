import { useState, useEffect, useCallback } from "react";
import type { SentinelMetricsSnapshot } from "@/types/sentinel";

const REFRESH_INTERVAL_MS = 10_000;

interface Props {
  readonly apiBase?: string;
}

function formatRate(flagged: number, scanned: number): string {
  if (scanned === 0) return "0.0000%";
  return `${((flagged / scanned) * 100).toFixed(4)}%`;
}

export function SentinelMetricsPanel({ apiBase }: Props) {
  const [metrics, setMetrics] = useState<SentinelMetricsSnapshot | null>(null);
  const [error, setError] = useState(false);

  const base = apiBase ?? "/sentinel/metrics";

  const fetchMetrics = useCallback(async () => {
    try {
      const resp = await fetch(base);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data: SentinelMetricsSnapshot = await resp.json();
      setMetrics(data);
      setError(false);
    } catch {
      setError(true);
    }
  }, [base]);

  useEffect(() => {
    void fetchMetrics();
    const timer = setInterval(() => void fetchMetrics(), REFRESH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [fetchMetrics]);

  if (error && metrics === null) {
    return (
      <section>
        <p className="text-sm text-slate-500">Unable to load metrics</p>
      </section>
    );
  }

  const s = metrics ?? {
    blocks_scanned: 0,
    txs_scanned: 0,
    txs_flagged: 0,
    alerts_emitted: 0,
  };

  return (
    <section className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
      <div className="bg-sentinel-card border border-sentinel-border p-5 rounded-xl shadow-lg">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">
          Blocks Scanned
        </p>
        <div className="flex items-end justify-between">
          <h3 className="text-2xl font-bold">{s.blocks_scanned.toLocaleString()}</h3>
          <span className="text-sentinel-connected text-sm font-medium flex items-center">
            <span className="material-symbols-outlined text-xs">trending_up</span>
          </span>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border p-5 rounded-xl shadow-lg">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">
          TXs Scanned
        </p>
        <div className="flex items-end justify-between">
          <h3 className="text-2xl font-bold">{s.txs_scanned.toLocaleString()}</h3>
          <span className="text-sentinel-connected text-sm font-medium flex items-center">
            <span className="material-symbols-outlined text-xs">trending_up</span>
          </span>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border p-5 rounded-xl shadow-lg border-l-4 border-l-sentinel-high">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">
          TXs Flagged
        </p>
        <div className="flex items-end justify-between">
          <h3 className="text-2xl font-bold text-sentinel-high">
            {s.txs_flagged.toLocaleString()}
          </h3>
          <span className="text-sentinel-high text-sm font-medium flex items-center">
            <span className="material-symbols-outlined text-xs">warning</span>
          </span>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border p-5 rounded-xl shadow-lg border-l-4 border-l-sentinel-critical">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">
          Alerts Emitted
        </p>
        <div className="flex items-end justify-between">
          <h3 className="text-2xl font-bold text-sentinel-critical">
            {s.alerts_emitted.toLocaleString()}
          </h3>
          <span className="text-sentinel-critical text-sm font-medium flex items-center">
            <span className="material-symbols-outlined text-xs">notification_important</span>
          </span>
        </div>
      </div>

      <div className="bg-sentinel-card border border-sentinel-border p-5 rounded-xl shadow-lg">
        <p className="text-slate-400 text-xs font-medium uppercase tracking-wider mb-1">
          Flag Rate
        </p>
        <div className="flex items-end justify-between">
          <h3 className="text-2xl font-bold text-sentinel-connected">
            {formatRate(s.txs_flagged, s.txs_scanned)}
          </h3>
          <span className="text-sentinel-connected text-sm font-medium flex items-center">
            <span className="material-symbols-outlined text-xs">trending_down</span>
          </span>
        </div>
      </div>
    </section>
  );
}
