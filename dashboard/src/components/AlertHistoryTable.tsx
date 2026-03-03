import { useState, useEffect, useCallback } from "react";
import type {
  AlertPriority,
  AlertQueryParams,
  AlertQueryResult,
  SentinelAlert,
} from "@/types/sentinel";
import { AlertCard } from "./AlertCard";

const DEFAULT_PAGE_SIZE = 20;

interface Props {
  readonly apiBase?: string;
}

interface Filters {
  readonly priority: AlertPriority | "";
  readonly blockFrom: string;
  readonly blockTo: string;
  readonly patternType: string;
}

const INITIAL_FILTERS: Filters = {
  priority: "",
  blockFrom: "",
  blockTo: "",
  patternType: "",
};

function buildQueryString(page: number, filters: Filters): string {
  const params: AlertQueryParams = {
    page,
    page_size: DEFAULT_PAGE_SIZE,
    ...(filters.priority !== "" ? { priority: filters.priority } : {}),
    ...(filters.blockFrom !== "" ? { block_from: Number(filters.blockFrom) } : {}),
    ...(filters.blockTo !== "" ? { block_to: Number(filters.blockTo) } : {}),
    ...(filters.patternType !== "" ? { pattern_type: filters.patternType } : {}),
  };

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    qs.set(k, String(v));
  }
  return qs.toString();
}

function Skeleton() {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: 3 }, (_, i) => (
        <div
          key={i}
          className="h-20 animate-pulse rounded-lg border border-tokamak-border bg-tokamak-card"
        />
      ))}
    </div>
  );
}

export function AlertHistoryTable({ apiBase }: Props) {
  const [alerts, setAlerts] = useState<readonly SentinelAlert[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState<Filters>(INITIAL_FILTERS);

  const base = apiBase ?? "/sentinel/history";
  const totalPages = Math.max(1, Math.ceil(total / DEFAULT_PAGE_SIZE));

  const fetchAlerts = useCallback(
    async (currentPage: number, currentFilters: Filters) => {
      setLoading(true);
      try {
        const qs = buildQueryString(currentPage, currentFilters);
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
    [base],
  );

  useEffect(() => {
    void fetchAlerts(page, filters);
  }, [page, filters, fetchAlerts]);

  const updateFilter = <K extends keyof Filters>(key: K, value: Filters[K]) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
    setPage(1);
  };

  return (
    <section>
      <h2 className="mb-4 text-lg font-semibold text-white">Alert History</h2>

      {/* Filter controls */}
      <div className="mb-4 flex flex-wrap gap-3">
        <select
          className="rounded border border-tokamak-border bg-tokamak-card px-2 py-1 text-sm text-white"
          value={filters.priority}
          onChange={(e) => updateFilter("priority", e.target.value as AlertPriority | "")}
          aria-label="Priority filter"
        >
          <option value="">All Priorities</option>
          <option value="Medium">Medium</option>
          <option value="High">High</option>
          <option value="Critical">Critical</option>
        </select>

        <input
          type="number"
          placeholder="Block from"
          className="w-28 rounded border border-tokamak-border bg-tokamak-card px-2 py-1 text-sm text-white placeholder-slate-500"
          value={filters.blockFrom}
          onChange={(e) => updateFilter("blockFrom", e.target.value)}
          aria-label="Block from"
        />

        <input
          type="number"
          placeholder="Block to"
          className="w-28 rounded border border-tokamak-border bg-tokamak-card px-2 py-1 text-sm text-white placeholder-slate-500"
          value={filters.blockTo}
          onChange={(e) => updateFilter("blockTo", e.target.value)}
          aria-label="Block to"
        />

        <input
          type="text"
          placeholder="Pattern type"
          className="w-36 rounded border border-tokamak-border bg-tokamak-card px-2 py-1 text-sm text-white placeholder-slate-500"
          value={filters.patternType}
          onChange={(e) => updateFilter("patternType", e.target.value)}
          aria-label="Pattern type"
        />
      </div>

      {/* Content */}
      {loading ? (
        <Skeleton />
      ) : alerts.length === 0 ? (
        <p className="text-sm text-slate-500">No alerts found</p>
      ) : (
        <div className="flex flex-col gap-3">
          {alerts.map((alert, i) => (
            <AlertCard key={`${alert.tx_hash}-${i}`} alert={alert} />
          ))}
        </div>
      )}

      {/* Pagination */}
      <div className="mt-4 flex items-center justify-between">
        <button
          type="button"
          disabled={page <= 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          className="rounded border border-tokamak-border px-3 py-1 text-sm text-white disabled:opacity-40"
        >
          Previous
        </button>
        <span className="text-sm text-slate-400">
          Page {page} of {totalPages}
        </span>
        <button
          type="button"
          disabled={page >= totalPages}
          onClick={() => setPage((p) => p + 1)}
          className="rounded border border-tokamak-border px-3 py-1 text-sm text-white disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </section>
  );
}
