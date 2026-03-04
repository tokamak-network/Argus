type ConnectionStatus = "connecting" | "connected" | "disconnected";

interface Props {
  readonly status: ConnectionStatus;
}

const STATUS_CONFIG = {
  connecting: {
    dot: "bg-sentinel-medium animate-pulse",
    label: "Connecting...",
    labelClass: "text-sentinel-medium",
  },
  connected: {
    dot: "bg-sentinel-connected",
    label: "Connected",
    labelClass: "text-sentinel-connected",
  },
  disconnected: {
    dot: "bg-sentinel-critical",
    label: "Disconnected",
    labelClass: "text-sentinel-critical",
  },
} as const;

const STEPS = [
  {
    number: "1",
    title: "Configure Your RPC Endpoint",
    description:
      "Set your Ethereum node RPC URL in the Sentinel configuration file or via environment variable.",
    code: "argus sentinel --rpc https://eth-mainnet.g.alchemy.com/v2/KEY",
  },
  {
    number: "2",
    title: "Start the Sentinel Service",
    description:
      "Run the Argus Sentinel process. It will begin scanning blocks and emitting alerts in real time.",
    code: "argus sentinel --config sentinel.toml --metrics-port 9090",
  },
  {
    number: "3",
    title: "Monitor Live Alerts",
    description:
      "Once connected, the dashboard will stream live alerts as Sentinel detects suspicious transactions.",
    code: null,
  },
] as const;

function ShieldGlowIcon() {
  return (
    <div className="relative flex items-center justify-center">
      <div
        className="relative flex h-20 w-20 items-center justify-center rounded-full border border-sentinel-primary/30 bg-sentinel-primary/10"
        style={{ boxShadow: "0 0 20px rgba(6,182,212,0.3)" }}
      >
        <svg
          width="40"
          height="40"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="text-sentinel-primary"
          aria-hidden="true"
        >
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      </div>
    </div>
  );
}

export default function EmptyState({ status }: Props) {
  const statusCfg = STATUS_CONFIG[status];

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="flex w-full max-w-4xl flex-col items-center gap-8 text-center">

        {/* Hero */}
        <ShieldGlowIcon />

        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-bold tracking-tight text-white">Argus Sentinel</h1>
          <p className="text-base text-slate-400">Ethereum Attack Detection Monitor</p>
        </div>

        {/* Connection Status Card */}
        <div className="flex items-center gap-3 rounded-xl border border-sentinel-border bg-sentinel-card px-6 py-3">
          <span
            className={`inline-flex h-2.5 w-2.5 rounded-full ${statusCfg.dot}`}
            aria-hidden="true"
          />
          <span className="text-sm font-medium text-slate-300">Connection Status:</span>
          <span className={`text-sm font-semibold ${statusCfg.labelClass}`}>
            {statusCfg.label}
          </span>
        </div>

        {/* Getting Started Steps */}
        <div className="w-full rounded-xl border border-sentinel-border bg-sentinel-card p-6 text-left">
          <h2 className="mb-5 text-base font-semibold text-white">Getting Started</h2>
          <ol className="flex flex-col gap-6">
            {STEPS.map((step) => (
              <li key={step.number} className="flex gap-4">
                <span className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-full border border-sentinel-primary/40 bg-sentinel-primary/10 text-sm font-bold text-sentinel-primary">
                  {step.number}
                </span>
                <div className="flex flex-col gap-1">
                  <p className="text-sm font-semibold text-white">{step.title}</p>
                  <p className="text-sm text-slate-400">{step.description}</p>
                  {step.code !== null && (
                    <code className="mt-1 block rounded-md border border-sentinel-border bg-sentinel-bg px-3 py-2 font-mono text-xs text-sentinel-primary">
                      {step.code}
                    </code>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-center gap-3">
          <a
            href="https://github.com/tokamak-network/Argus"
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-sentinel-border px-6 py-2.5 text-sm font-bold text-slate-200 transition-colors hover:bg-sentinel-card"
          >
            View Documentation
          </a>
          <a
            href="/sentinel"
            className="rounded-lg border border-sentinel-border px-6 py-2.5 text-sm font-bold text-slate-200 transition-colors hover:bg-sentinel-card"
          >
            Configure Sentinel
          </a>
          <button
            type="button"
            className="rounded-lg bg-sentinel-primary px-6 py-2.5 text-sm font-bold text-white shadow-lg shadow-sentinel-primary/20 transition-opacity hover:opacity-90"
          >
            Check Connection
          </button>
        </div>

        {/* Footer */}
        <div className="flex flex-col items-center gap-1 text-xs text-slate-600">
          <span>Powered by Argus v0.2.0</span>
          <span className="tracking-widest">SECURE / VIGILANT / ANOMALY-AWARE</span>
        </div>

      </div>
    </div>
  );
}
