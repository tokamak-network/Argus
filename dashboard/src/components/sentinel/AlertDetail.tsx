import { useState, useEffect, useCallback } from "react";
import type { SentinelAlert, AlertPriority } from "@/types/sentinel";
import SuspicionScoreGauge from "./SuspicionScoreGauge";
import DetectedPatterns from "./DetectedPatterns";

interface Props {
  readonly apiBase?: string;
}

const PRIORITY_STYLES: Record<AlertPriority, string> = {
  Critical: "bg-sentinel-critical/15 text-sentinel-critical border-sentinel-critical/30",
  High: "bg-sentinel-high/15 text-sentinel-high border-sentinel-high/30",
  Medium: "bg-sentinel-medium/15 text-sentinel-medium border-sentinel-medium/30",
};

function formatValue(hex: string): string {
  if (!hex || hex === "0x0" || hex === "0") return "0 ETH";
  try {
    const wei = BigInt(hex);
    const eth = Number(wei) / 1e18;
    if (eth === 0) return "0 ETH";
    return `${eth.toFixed(4)} ETH`;
  } catch {
    return hex;
  }
}

export default function AlertDetail({ apiBase }: Props) {
  const [alert, setAlert] = useState<SentinelAlert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const base = apiBase ?? "/sentinel/history";

  const fetchAlert = useCallback(async () => {
    const params = new URLSearchParams(window.location.search);
    const txHash = params.get("tx");

    if (!txHash) {
      setError("No transaction hash provided");
      setLoading(false);
      return;
    }

    try {
      const resp = await fetch(`${base}?page=1&page_size=100`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = await resp.json();
      const found = data.alerts.find(
        (a: SentinelAlert) => a.tx_hash === txHash,
      );
      if (found) {
        setAlert(found);
      } else {
        setError("Alert not found");
      }
    } catch {
      setError("Failed to load alert data");
    } finally {
      setLoading(false);
    }
  }, [base]);

  useEffect(() => {
    void fetchAlert();
  }, [fetchAlert]);

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-8 w-48 animate-pulse rounded bg-sentinel-surface" />
        <div className="h-40 animate-pulse rounded-xl bg-sentinel-surface" />
        <div className="h-64 animate-pulse rounded-xl bg-sentinel-surface" />
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-8 text-center">
        <span className="material-symbols-outlined text-4xl text-slate-500 mb-4 block">error</span>
        <p className="text-slate-400">{error ?? "Alert not found"}</p>
        <a href="/sentinel" className="mt-4 inline-block text-sm text-sentinel-primary hover:underline">
          Back to Dashboard
        </a>
      </div>
    );
  }

  const priorityStyle = PRIORITY_STYLES[alert.alert_priority];
  const patterns = alert.detected_patterns ?? [];
  const fundFlows = alert.fund_flows ?? [];

  return (
    <div className="space-y-8">
      {/* Breadcrumbs */}
      <nav className="flex items-center gap-2 text-sm text-slate-500">
        <a href="/sentinel" className="hover:text-sentinel-primary transition-colors">Dashboard</a>
        <span>/</span>
        <a href="/sentinel/history" className="hover:text-sentinel-primary transition-colors">Alerts</a>
        <span>/</span>
        <span className="text-white">Block #{alert.block_number.toLocaleString()}</span>
      </nav>

      {/* Alert Header Card */}
      <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-3">
              <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${priorityStyle}`}>
                {alert.alert_priority}
              </span>
              <span className="text-4xl font-bold text-white">
                Block #{alert.block_number.toLocaleString()}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-sentinel-primary" title={alert.tx_hash}>
                {alert.tx_hash}
              </span>
              <button
                type="button"
                onClick={() => void navigator.clipboard.writeText(alert.tx_hash)}
                className="text-slate-500 hover:text-sentinel-primary transition-colors"
              >
                <span className="material-symbols-outlined text-base">content_copy</span>
              </button>
            </div>
          </div>
          <div className="flex flex-col items-end gap-1 text-right">
            <span className="text-xs text-slate-500">Value at Risk</span>
            <span className="text-2xl font-bold text-sentinel-critical">
              {formatValue(alert.total_value_at_risk)}
            </span>
          </div>
        </div>
        <p className="mt-4 text-sm text-slate-400">{alert.summary}</p>
      </div>

      {/* Main Grid */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column (span 2) */}
        <div className="flex flex-col gap-6 lg:col-span-2">
          <SuspicionScoreGauge score={alert.suspicion_score} />

          {/* Analysis Summary */}
          <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
            <p className="mb-3 text-sm font-medium text-slate-400">Analysis Summary</p>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <div>
                <p className="text-xs text-slate-500">EVM Steps</p>
                <p className="text-xl font-bold text-white">{alert.total_steps.toLocaleString()}</p>
              </div>
              <div>
                <p className="text-xs text-slate-500">Detection Score</p>
                <p className="text-xl font-bold text-sentinel-critical">{alert.suspicion_score.toFixed(2)}</p>
              </div>
              <div>
                <p className="text-xs text-slate-500">Suspicion Reasons</p>
                <p className="text-xl font-bold text-white">{alert.suspicion_reasons.length}</p>
              </div>
            </div>
          </div>

          {patterns.length > 0 && <DetectedPatterns patterns={patterns} />}
        </div>

        {/* Right Column */}
        <div className="flex flex-col gap-6">
          {/* Suspicion Reasons */}
          <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
            <p className="mb-3 text-sm font-medium text-slate-400">Suspicion Reasons</p>
            <ul className="flex flex-col gap-3">
              {alert.suspicion_reasons.map((reason, i) => (
                <li key={i} className="flex flex-col gap-1 rounded-lg border border-sentinel-border bg-sentinel-bg p-3">
                  <span className="text-sm font-semibold text-sentinel-primary">{reason.type}</span>
                  {reason.details && typeof reason.details === "object" && (
                    <div className="text-xs text-slate-400 space-y-0.5">
                      {Object.entries(reason.details).map(([k, v]) => (
                        <div key={k}>
                          <span className="text-slate-500">{k}:</span>{" "}
                          <span className="font-mono">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {/* Fund Flows */}
          {fundFlows.length > 0 && (
            <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
              <p className="mb-3 text-sm font-medium text-slate-400">Fund Flows</p>
              <ul className="flex flex-col gap-3">
                {fundFlows.map((flow: { from: string; to: string; value: string }, i: number) => (
                  <li key={i} className="flex flex-col gap-1 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full bg-sentinel-primary/20 text-sentinel-primary font-bold">
                        {i + 1}
                      </span>
                      <span className="font-mono text-slate-300">{flow.value}</span>
                    </div>
                    <div className="ml-7 flex flex-col gap-0.5 text-slate-500">
                      <span>From: {flow.from}</span>
                      <span>To: {flow.to}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex flex-wrap items-center gap-3">
        <a
          href="/sentinel/history"
          className="rounded-lg border border-sentinel-border px-5 py-2.5 text-sm font-semibold text-slate-300 transition-colors hover:border-sentinel-border-light hover:text-white"
        >
          Back to History
        </a>
        <a
          href={`https://etherscan.io/tx/${alert.tx_hash}`}
          target="_blank"
          rel="noopener noreferrer"
          className="rounded-lg bg-sentinel-primary px-5 py-2.5 text-sm font-semibold text-white transition-opacity hover:opacity-90 flex items-center gap-2"
        >
          View on Etherscan
          <span className="material-symbols-outlined text-sm">open_in_new</span>
        </a>
      </div>
    </div>
  );
}
