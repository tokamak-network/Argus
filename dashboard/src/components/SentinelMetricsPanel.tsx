import { useState, useEffect, useCallback } from "react";
import type { SentinelMetricsSnapshot } from "@/types/sentinel";

const REFRESH_INTERVAL_MS = 10_000;

interface Props {
  readonly apiBase?: string;
}

function formatRate(flagged: number, scanned: number): string {
  if (scanned === 0) return "0.00%";
  return `${((flagged / scanned) * 100).toFixed(2)}%`;
}

function MetricTile({
  label,
  value,
}: {
  readonly label: string;
  readonly value: string;
}) {
  return (
    <div className="rounded-lg border border-tokamak-border bg-tokamak-card p-4">
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-white">{value}</p>
    </div>
  );
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
        <h2 className="mb-4 text-lg font-semibold text-white">Sentinel Metrics</h2>
        <p className="text-sm text-slate-500">Unable to load metrics</p>
      </section>
    );
  }

  const snapshot = metrics ?? {
    blocks_scanned: 0,
    txs_scanned: 0,
    txs_flagged: 0,
    alerts_emitted: 0,
  };

  return (
    <section>
      <h2 className="mb-4 text-lg font-semibold text-white">Sentinel Metrics</h2>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <MetricTile
          label="Blocks Scanned"
          value={snapshot.blocks_scanned.toLocaleString()}
        />
        <MetricTile
          label="TXs Scanned"
          value={snapshot.txs_scanned.toLocaleString()}
        />
        <MetricTile
          label="TXs Flagged"
          value={snapshot.txs_flagged.toLocaleString()}
        />
        <MetricTile
          label="Alerts Emitted"
          value={snapshot.alerts_emitted.toLocaleString()}
        />
        <MetricTile
          label="Flag Rate"
          value={formatRate(snapshot.txs_flagged, snapshot.txs_scanned)}
        />
      </div>
    </section>
  );
}
