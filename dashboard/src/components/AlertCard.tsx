import { useState } from "react";
import type { SentinelAlert } from "@/types/sentinel";
import { AlertPriorityBadge } from "./AlertPriorityBadge";

interface Props {
  readonly alert: SentinelAlert;
}

function truncateHash(hash: string): string {
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 8)}...${hash.slice(-4)}`;
}

export function AlertCard({ alert }: Props) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-tokamak-border bg-tokamak-card p-4">
      <button
        type="button"
        className="flex w-full items-center justify-between text-left"
        onClick={() => setExpanded((prev) => !prev)}
        aria-expanded={expanded}
      >
        <div className="flex items-center gap-3">
          <AlertPriorityBadge priority={alert.alert_priority} />
          <span className="font-mono text-sm text-slate-300" title={alert.tx_hash}>
            {truncateHash(alert.tx_hash)}
          </span>
          <span className="text-xs text-slate-500">Block #{alert.block_number}</span>
        </div>
        <span className="text-xs text-slate-500">{expanded ? "−" : "+"}</span>
      </button>

      <p className="mt-2 text-sm text-slate-400">{alert.summary}</p>

      {expanded && (
        <div className="mt-3 border-t border-tokamak-border pt-3">
          {alert.suspicion_reasons.length > 0 && (
            <div className="mb-2">
              <p className="text-xs font-medium text-slate-400">Suspicion Reasons</p>
              <ul className="mt-1 list-inside list-disc text-xs text-slate-500">
                {alert.suspicion_reasons.map((reason, i) => (
                  <li key={i}>{reason.type}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="flex gap-4 text-xs text-slate-500">
            <span>Value at risk: {alert.total_value_at_risk}</span>
            <span>Steps: {alert.total_steps.toLocaleString()}</span>
            <span>Score: {alert.suspicion_score.toFixed(2)}</span>
          </div>
        </div>
      )}
    </div>
  );
}
