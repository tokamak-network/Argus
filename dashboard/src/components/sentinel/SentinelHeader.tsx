interface SentinelHeaderProps {
  currentPath: string;
}

const navItems = [
  { label: "Dashboard", href: "/sentinel" },
  { label: "Alert History", href: "/sentinel/history" },
] as const;

function isActive(currentPath: string, href: string): boolean {
  if (href === "/sentinel") {
    return currentPath === "/sentinel" || currentPath === "/sentinel/";
  }
  return currentPath.startsWith(href);
}

export default function SentinelHeader({ currentPath }: SentinelHeaderProps) {
  return (
    <header className="flex items-center justify-between border-b border-sentinel-border px-8 py-4 bg-sentinel-bg/50 backdrop-blur-md sticky top-0 z-50">
      <div className="flex items-center gap-8">
        <a href="/sentinel" className="flex items-center gap-3">
          <div className="text-sentinel-primary flex items-center justify-center">
            <span className="material-symbols-outlined text-3xl">shield_with_heart</span>
          </div>
          <h1 className="text-xl font-bold tracking-tight uppercase text-white">
            Argus Sentinel
          </h1>
        </a>
        <nav className="hidden md:flex items-center gap-6">
          {navItems.map(({ label, href }) => {
            const active = isActive(currentPath, href);
            return (
              <a
                key={href}
                href={href}
                className={
                  active
                    ? "text-sm font-semibold text-sentinel-primary border-b-2 border-sentinel-primary pb-1"
                    : "text-sm font-medium text-slate-400 hover:text-sentinel-primary transition-colors pb-1"
                }
              >
                {label}
              </a>
            );
          })}
        </nav>
      </div>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 bg-sentinel-primary/10 border border-sentinel-primary/30 rounded-lg px-4 py-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sentinel-connected opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-sentinel-connected" />
          </span>
          <span className="text-sm font-semibold text-sentinel-primary">WebSocket: Connected</span>
        </div>
        <div className="flex items-center gap-2 bg-sentinel-border rounded-lg px-4 py-2">
          <span className="material-symbols-outlined text-sm">timer</span>
          <span className="text-sm font-medium">Live</span>
        </div>
        <button className="p-2 hover:bg-sentinel-border rounded-lg transition-colors">
          <span className="material-symbols-outlined">settings</span>
        </button>
      </div>
    </header>
  );
}
