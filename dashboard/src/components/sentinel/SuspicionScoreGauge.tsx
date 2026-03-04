interface Props {
  readonly score: number;
}

function scoreColor(score: number): string {
  if (score >= 0.75) return "text-sentinel-critical";
  if (score >= 0.5) return "text-sentinel-high";
  return "text-sentinel-medium";
}

function scoreLabel(score: number): string {
  if (score >= 0.75) return "Critical Risk";
  if (score >= 0.5) return "High Risk";
  return "Medium Risk";
}

export default function SuspicionScoreGauge({ score }: Props) {
  const clampedScore = Math.min(1, Math.max(0, score));
  const pct = Math.round(clampedScore * 100);

  return (
    <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
      <p className="mb-3 text-sm font-medium text-slate-400">Suspicion Score</p>

      <div className="flex items-center gap-4">
        <span className={`text-3xl font-bold ${scoreColor(clampedScore)}`}>
          {clampedScore.toFixed(2)}
        </span>
        <span className={`text-sm font-semibold ${scoreColor(clampedScore)}`}>
          {scoreLabel(clampedScore)}
        </span>
      </div>

      <div className="mt-4 h-3 w-full overflow-hidden rounded-full bg-sentinel-border">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(to right, #06b6d4, #eab308 50%, #ef4444)`,
          }}
        />
      </div>

      <div className="mt-1 flex justify-between text-xs text-slate-500">
        <span>0.00</span>
        <span>0.50</span>
        <span>1.00</span>
      </div>
    </div>
  );
}
