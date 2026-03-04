import { useState, useEffect, useCallback } from "react";
import type {
  AlertPriority,
  AlertQueryParams,
  AlertQueryResult,
  SentinelAlert,
} from "@/types/sentinel";
import { AlertPriorityBadge } from "./AlertPriorityBadge";

const DEFAULT_PAGE_SIZE = 20;

interface Props {
  readonly apiBase?: string;
  readonly compact?: boolean;
}

interface Filters {
  readonly priority: AlertPriority | "";
  readonly blockFrom: string;
  readonly blockTo: string;
  readonly keyword: string;
}

const INITIAL_FILTERS: Filters = {
  priority: "",
  blockFrom: "",
  blockTo: "",
  keyword: "",
};

function buildQueryString(page: number, pageSize: number, filters: Filters): string {
  const params: AlertQueryParams = {
    page,
    page_size: pageSize,
    ...(filters.priority !== "" ? { priority: filters.priority } : {}),
    ...(filters.blockFrom !== ""
      ? { block_from: Number(filters.blockFrom) }
      : {}),
    ...(filters.blockTo !== "" ? { block_to: Number(filters.blockTo) } : {}),
  };

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    qs.set(k, String(v));
  }
  return qs.toString();
}

function truncateHash(hash: string): string {
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 6)}...${hash.slice(-4)}`;
}

function Skeleton() {
  return (
    <div className="space-y-2">
      {Array.from({ length: 5 }, (_, i) => (
        <div
          key={i}
          className="h-12 animate-pulse rounded bg-sentinel-surface"
        />
      ))}
    </div>
  );
}

function pageNumbers(current: number, total: number): readonly number[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  const pages = new Set<number>([1, total, current]);
  if (current > 1) pages.add(current - 1);
  if (current < total) pages.add(current + 1);
  return [...pages].sort((a, b) => a - b);
}

function CopyButton({ text }: { readonly text: string }) {
  const handleCopy = () => {
    void navigator.clipboard.writeText(text);
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="text-slate-500 hover:text-sentinel-primary transition-colors"
      title="Copy to clipboard"
    >
      <span className="material-symbols-outlined text-base">content_copy</span>
    </button>
  );
}

export function AlertHistoryTable({ apiBase, compact = false }: Props) {
  const pageSize = compact ? 5 : DEFAULT_PAGE_SIZE;
  const [alerts, setAlerts] = useState<readonly SentinelAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS);
  const [pendingFilters, setPendingFilters] = useState<Filters>(INITIAL_FILTERS);

  const base = apiBase ?? "/sentinel/history";
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const fetchAlerts = useCallback(
    async (currentPage: number, currentFilters: Filters) => {
      setLoading(true);
      try {
        const qs = buildQueryString(currentPage, pageSize, currentFilters);
        const resp = await fetch(`${base}?${qs}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data: AlertQueryResult = await resp.json();
        setAlerts(data.alerts);
        setTotal(data.total);
      } catch {
        setAlerts([]);
        setTotal(0);
      } finally {
        setLoading(false);
      }
    },
    [base, pageSize],
  );

  useEffect(() => {
    void fetchAlerts(page, filters);
  }, [page, filters, fetchAlerts]);

  const applyFilters = () => {
    setFilters(pendingFilters);
    setPage(1);
  };

  const updatePending = <K extends keyof Filters>(key: K, value: Filters[K]) => {
    setPendingFilters((prev) => ({ ...prev, [key]: value }));
  };

  const inputClass =
    "w-full bg-sentinel-bg border border-sentinel-border-light text-slate-100 rounded-lg h-11 px-4 focus:ring-sentinel-primary focus:border-sentinel-primary placeholder:text-slate-600 text-sm";

  const criticalCount = alerts.filter((a) => a.alert_priority === "Critical").length;

  return (
    <section className="space-y-6">
      {/* Filter card (hidden in compact mode) */}
      {!compact && (
        <div className="bg-sentinel-surface border border-sentinel-border-light rounded-xl p-6">
          <div className="grid grid-cols-1 md:grid-cols-4 lg:grid-cols-5 gap-6 items-end">
            <div className="flex flex-col gap-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                Priority
              </label>
              <div className="relative">
                <select
                  className={inputClass + " appearance-none"}
                  value={pendingFilters.priority}
                  onChange={(e) =>
                    updatePending("priority", e.target.value as AlertPriority | "")
                  }
                  aria-label="Priority filter"
                >
                  <option value="">All Priorities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                </select>
                <span className="material-symbols-outlined absolute right-3 top-2.5 text-slate-500 pointer-events-none">
                  expand_more
                </span>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                From Block
              </label>
              <input
                type="number"
                placeholder="18,450,000"
                className={inputClass}
                value={pendingFilters.blockFrom}
                onChange={(e) => updatePending("blockFrom", e.target.value)}
                aria-label="Block from"
              />
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                To Block
              </label>
              <input
                type="number"
                placeholder="Latest"
                className={inputClass}
                value={pendingFilters.blockTo}
                onChange={(e) => updatePending("blockTo", e.target.value)}
                aria-label="Block to"
              />
            </div>

            <div className="flex flex-col gap-2">
              <label className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                Keyword Search
              </label>
              <input
                type="text"
                placeholder="Summary or Pattern..."
                className={inputClass}
                value={pendingFilters.keyword}
                onChange={(e) => updatePending("keyword", e.target.value)}
                aria-label="Keyword search"
              />
            </div>

            <div className="flex items-center h-11">
              <button
                type="button"
                onClick={applyFilters}
                className="w-full bg-sentinel-primary hover:bg-sentinel-primary/90 text-white font-bold rounded-lg h-full flex items-center justify-center gap-2 transition-all shadow-lg shadow-sentinel-primary/20"
              >
                <span className="material-symbols-outlined text-sm">search</span>
                Apply Filters
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <Skeleton />
      ) : alerts.length === 0 ? (
        <p className="text-sm text-slate-500">No alerts found</p>
      ) : (
        <div className="bg-sentinel-surface border border-sentinel-border-light rounded-xl overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-sentinel-bg/50 border-b border-sentinel-border-light">
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest">
                    Block #
                  </th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest">
                    TX Hash
                  </th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest">
                    Priority
                  </th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest text-center">
                    Score
                  </th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest">
                    Summary
                  </th>
                  <th className="px-6 py-4 text-xs font-bold text-slate-400 uppercase tracking-widest">
                    Patterns
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border-light/50">
                {alerts.map((alert, i) => (
                  <tr
                    key={`${alert.tx_hash}-${i}`}
                    className={`hover:bg-sentinel-primary/5 transition-colors ${
                      i % 2 !== 0 ? "bg-sentinel-bg/20" : ""
                    }`}
                  >
                    <td className="px-6 py-4 font-mono text-sm text-sentinel-primary">
                      {alert.block_number.toLocaleString()}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <a
                          href={`/sentinel/alert?tx=${encodeURIComponent(alert.tx_hash)}`}
                          className="font-mono text-sm text-slate-300 hover:text-sentinel-primary transition-colors"
                          title={alert.tx_hash}
                        >
                          {truncateHash(alert.tx_hash)}
                        </a>
                        <CopyButton text={alert.tx_hash} />
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <AlertPriorityBadge priority={alert.alert_priority} />
                    </td>
                    <td className="px-6 py-4 text-center">
                      <span className="font-bold text-slate-100">
                        {Math.round(alert.suspicion_score * 100)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-slate-300 max-w-xs truncate">
                      {alert.summary}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1.5">
                        {alert.suspicion_reasons.map((reason, j) => (
                          <span
                            key={j}
                            className="bg-sentinel-border-light text-slate-400 px-2 py-0.5 rounded text-[10px] font-semibold"
                          >
                            {reason.type}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination footer */}
          {!compact && (
            <div className="p-6 bg-sentinel-bg/30 border-t border-sentinel-border-light flex flex-col sm:flex-row items-center justify-between gap-4">
              <p className="text-sm text-slate-500">
                Page{" "}
                <span className="text-slate-100 font-semibold">{page}</span> of{" "}
                <span className="text-slate-100 font-semibold">{totalPages}</span>
                <span className="ml-2 text-slate-600">({total} total alerts)</span>
              </p>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="flex items-center justify-center h-9 px-4 rounded-lg bg-sentinel-surface border border-sentinel-border-light text-slate-400 hover:text-slate-100 hover:border-slate-500 transition-all text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <span className="material-symbols-outlined text-lg mr-1">chevron_left</span>
                  Previous
                </button>
                <div className="flex items-center gap-1 mx-2">
                  {pageNumbers(page, totalPages).map((num, idx, arr) => {
                    const showGap = idx > 0 && num - arr[idx - 1] > 1;
                    return (
                      <span key={num} className="flex items-center gap-1">
                        {showGap && (
                          <span className="px-1 text-xs text-slate-500">...</span>
                        )}
                        <button
                          type="button"
                          onClick={() => setPage(num)}
                          className={`size-9 flex items-center justify-center rounded-lg text-sm font-bold transition-colors ${
                            num === page
                              ? "bg-sentinel-primary text-white"
                              : "hover:bg-sentinel-surface text-slate-400 hover:text-slate-100"
                          }`}
                        >
                          {num}
                        </button>
                      </span>
                    );
                  })}
                </div>
                <button
                  type="button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                  className="flex items-center justify-center h-9 px-4 rounded-lg bg-sentinel-surface border border-sentinel-border-light text-slate-400 hover:text-slate-100 hover:border-slate-500 transition-all text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Next
                  <span className="material-symbols-outlined text-lg ml-1">chevron_right</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Stats bar (full mode only) */}
      {!compact && !loading && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-sentinel-surface border border-sentinel-border-light rounded-xl p-4 flex items-center gap-4">
            <div className="size-10 rounded-lg bg-sentinel-critical/10 flex items-center justify-center">
              <span className="material-symbols-outlined text-sentinel-critical">warning</span>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">
                Active Critical
              </p>
              <p className="text-xl font-black text-slate-100">
                {criticalCount} Alerts
              </p>
            </div>
          </div>
          <div className="bg-sentinel-surface border border-sentinel-border-light rounded-xl p-4 flex items-center gap-4">
            <div className="size-10 rounded-lg bg-sentinel-high/10 flex items-center justify-center">
              <span className="material-symbols-outlined text-sentinel-high">error</span>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">
                Total Alerts
              </p>
              <p className="text-xl font-black text-slate-100">{total}</p>
            </div>
          </div>
          <div className="bg-sentinel-surface border border-sentinel-border-light rounded-xl p-4 flex items-center gap-4">
            <div className="size-10 rounded-lg bg-sentinel-primary/10 flex items-center justify-center">
              <span className="material-symbols-outlined text-sentinel-primary">schedule</span>
            </div>
            <div>
              <p className="text-xs text-slate-500 font-bold uppercase tracking-wider">
                Last Sync
              </p>
              <p className="text-xl font-black text-slate-100">Just now</p>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
