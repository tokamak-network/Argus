import type { SentinelAlert, AlertPriority } from "@/types/sentinel";

interface Props {
  readonly alert: SentinelAlert;
}

const PRIORITY_STYLES: Record<
  AlertPriority,
  { text: string; bg: string; border: string; icon: string; gradient: string }
> = {
  Critical: {
    text: "text-sentinel-critical",
    bg: "bg-sentinel-critical/20",
    border: "border-sentinel-critical/30",
    icon: "biotech",
    gradient: "rgba(255,77,77,0.2)",
  },
  High: {
    text: "text-sentinel-high",
    bg: "bg-sentinel-high/20",
    border: "border-sentinel-high/30",
    icon: "query_stats",
    gradient: "rgba(255,165,0,0.2)",
  },
  Medium: {
    text: "text-sentinel-medium",
    bg: "bg-sentinel-medium/20",
    border: "border-sentinel-medium/30",
    icon: "trending_down",
    gradient: "rgba(234,179,8,0.2)",
  },
};

function truncateHash(hash: string): string {
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 6)}...${hash.slice(-3)}`;
}

export function AlertCard({ alert }: Props) {
  const style = PRIORITY_STYLES[alert.alert_priority];
  const score = alert.suspicion_score.toFixed(2);

  return (
    <div className="bg-sentinel-card/60 border border-sentinel-border p-5 rounded-xl flex items-center gap-6 hover:bg-sentinel-card transition-all group">
      {/* Score column */}
      <div className="flex flex-col items-center justify-center min-w-[80px] border-r border-sentinel-border pr-6">
        <div className={`${style.text} text-2xl font-black italic`}>{score}</div>
        <div className="text-[10px] text-slate-500 uppercase tracking-tighter">Score</div>
      </div>

      {/* Content */}
      <div className="flex-1 space-y-2">
        <div className="flex items-center gap-3">
          <span
            className={`${style.bg} ${style.text} text-[10px] font-bold px-2 py-0.5 rounded border ${style.border}`}
          >
            {alert.alert_priority.toUpperCase()}
          </span>
          <span className="text-slate-400 text-xs font-mono">
            TX: {truncateHash(alert.tx_hash)}
          </span>
          <span className="text-slate-400 text-xs font-mono">
            Block: {alert.block_number}
          </span>
        </div>
        <h4 className="text-lg font-bold group-hover:text-sentinel-primary transition-colors">
          {alert.summary}
        </h4>
        <div className="flex items-center gap-4 text-xs text-slate-500">
          <span className="flex items-center gap-1">
            <span className="material-symbols-outlined text-xs">schedule</span>
            Just now
          </span>
          {alert.suspicion_reasons.length > 0 && (
            <span className="flex items-center gap-1">
              <span className="material-symbols-outlined text-xs">category</span>
              {alert.suspicion_reasons[0].type}
            </span>
          )}
        </div>
      </div>

      {/* Thumbnail */}
      <div className="w-32 h-20 bg-slate-800 rounded-lg overflow-hidden border border-sentinel-border hidden lg:flex items-center justify-center"
        style={{
          background: `linear-gradient(to bottom right, rgba(19,91,236,0.2), ${style.gradient})`,
        }}
      >
        <span className="material-symbols-outlined text-3xl opacity-20">{style.icon}</span>
      </div>
    </div>
  );
}
