interface Props {
  readonly patterns: readonly string[];
}

const PATTERN_STYLES: Record<string, string> = {
  "Flash Loan": "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/30",
  "FlashLoan": "bg-sentinel-primary/15 text-sentinel-primary border-sentinel-primary/30",
  "Price Manipulation": "bg-sentinel-high/15 text-sentinel-high border-sentinel-high/30",
  "PriceManipulation": "bg-sentinel-high/15 text-sentinel-high border-sentinel-high/30",
  "Reentrancy": "bg-sentinel-critical/15 text-sentinel-critical border-sentinel-critical/30",
};

const DEFAULT_STYLE =
  "bg-slate-500/15 text-slate-300 border-slate-500/30";

function patternStyle(pattern: string): string {
  return PATTERN_STYLES[pattern] ?? DEFAULT_STYLE;
}

function formatPattern(pattern: string): string {
  return pattern.replace(/([A-Z])/g, " $1").trim();
}

export default function DetectedPatterns({ patterns }: Props) {
  if (patterns.length === 0) {
    return null;
  }

  return (
    <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
      <p className="mb-3 text-sm font-medium text-slate-400">Detected Patterns</p>
      <div className="flex flex-wrap gap-2">
        {patterns.map((pattern) => (
          <span
            key={pattern}
            className={`rounded-full border px-3 py-1 text-xs font-semibold ${patternStyle(pattern)}`}
          >
            {formatPattern(pattern)}
          </span>
        ))}
      </div>
    </div>
  );
}
