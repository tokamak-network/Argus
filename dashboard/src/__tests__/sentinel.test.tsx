import { describe, it, expect, afterEach, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, cleanup, waitFor, act } from "@testing-library/react";
import { AlertPriorityBadge } from "@/components/AlertPriorityBadge";
import { AlertCard } from "@/components/AlertCard";
import { AlertHistoryTable } from "@/components/AlertHistoryTable";
import { SentinelMetricsPanel } from "@/components/SentinelMetricsPanel";
import { AlertFeed, useWsReconnect } from "@/components/AlertFeed";
import type {
  SentinelAlert,
  AlertPriority,
  AlertQueryParams,
  AlertQueryResult,
  SentinelMetricsSnapshot,
  WsConnectionStatus,
} from "@/types/sentinel";

afterEach(cleanup);

// ---------------------------------------------------------------------------
// Test data factories
// ---------------------------------------------------------------------------

function makeAlert(overrides?: Partial<SentinelAlert>): SentinelAlert {
  return {
    block_number: 18500000,
    block_hash: "0xabc123",
    tx_hash: "0xdeadbeefcafebabe1234567890abcdef12345678deadbeefcafebabe12345678",
    tx_index: 0,
    alert_priority: "High",
    suspicion_reasons: [{ type: "FlashLoanSignature" }],
    suspicion_score: 0.75,
    total_value_at_risk: "1000000000000000000",
    summary: "Possible flash loan attack on Uniswap V3",
    total_steps: 5432,
    ...overrides,
  };
}

function makeQueryResult(alerts: readonly SentinelAlert[], total: number): AlertQueryResult {
  return { alerts, total, page: 1, page_size: 20 };
}

// ---------------------------------------------------------------------------
// Type assertion tests
// ---------------------------------------------------------------------------

describe("Sentinel TypeScript types", () => {
  it("AlertPriority accepts valid values", () => {
    const priorities: AlertPriority[] = ["Medium", "High", "Critical"];
    expect(priorities).toHaveLength(3);
  });

  it("SentinelAlert has all required fields", () => {
    const alert = makeAlert();
    expect(alert.block_number).toBeTypeOf("number");
    expect(alert.block_hash).toBeTypeOf("string");
    expect(alert.tx_hash).toBeTypeOf("string");
    expect(alert.tx_index).toBeTypeOf("number");
    expect(alert.alert_priority).toBeTypeOf("string");
    expect(alert.suspicion_reasons).toBeInstanceOf(Array);
    expect(alert.suspicion_score).toBeTypeOf("number");
    expect(alert.total_value_at_risk).toBeTypeOf("string");
    expect(alert.summary).toBeTypeOf("string");
    expect(alert.total_steps).toBeTypeOf("number");
  });

  it("AlertQueryParams has correct shape", () => {
    const params: AlertQueryParams = {
      page: 1,
      page_size: 20,
      priority: "Critical",
      block_from: 1000,
      block_to: 2000,
      pattern_type: "Reentrancy",
    };
    expect(params.page).toBe(1);
    expect(params.priority).toBe("Critical");
  });

  it("SentinelMetricsSnapshot has correct fields", () => {
    const snapshot: SentinelMetricsSnapshot = {
      blocks_scanned: 100,
      txs_scanned: 5000,
      txs_flagged: 12,
      alerts_emitted: 3,
    };
    expect(snapshot.blocks_scanned).toBe(100);
    expect(snapshot.alerts_emitted).toBe(3);
  });

  it("WsConnectionStatus accepts valid values", () => {
    const statuses: WsConnectionStatus[] = ["connected", "disconnected", "reconnecting"];
    expect(statuses).toHaveLength(3);
  });
});

// ---------------------------------------------------------------------------
// AlertPriorityBadge tests
// ---------------------------------------------------------------------------

describe("AlertPriorityBadge", () => {
  it("renders Medium with yellow styling", () => {
    render(<AlertPriorityBadge priority="Medium" />);
    const badge = screen.getByText("Medium");
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain("tokamak-yellow");
  });

  it("renders High with orange styling", () => {
    render(<AlertPriorityBadge priority="High" />);
    const badge = screen.getByText("High");
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain("orange");
  });

  it("renders Critical with red styling", () => {
    render(<AlertPriorityBadge priority="Critical" />);
    const badge = screen.getByText("Critical");
    expect(badge).toBeInTheDocument();
    expect(badge.className).toContain("tokamak-red");
  });
});

// ---------------------------------------------------------------------------
// AlertCard tests
// ---------------------------------------------------------------------------

describe("AlertCard", () => {
  it("renders compact view with priority, truncated hash, block, and summary", () => {
    render(<AlertCard alert={makeAlert()} />);
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("0xdeadbe...5678")).toBeInTheDocument();
    expect(screen.getByText(/Block #18500000/)).toBeInTheDocument();
    expect(screen.getByText("Possible flash loan attack on Uniswap V3")).toBeInTheDocument();
  });

  it("expands on click to show suspicion reasons and details", () => {
    render(<AlertCard alert={makeAlert()} />);

    // Details should not be visible initially
    expect(screen.queryByText("Suspicion Reasons")).not.toBeInTheDocument();

    // Click to expand
    fireEvent.click(screen.getByRole("button"));

    expect(screen.getByText("Suspicion Reasons")).toBeInTheDocument();
    expect(screen.getByText("FlashLoanSignature")).toBeInTheDocument();
    expect(screen.getByText(/Value at risk/)).toBeInTheDocument();
    expect(screen.getByText(/Steps: 5,432/)).toBeInTheDocument();
  });

  it("collapses when clicked again", () => {
    render(<AlertCard alert={makeAlert()} />);

    fireEvent.click(screen.getByRole("button")); // expand
    expect(screen.getByText("Suspicion Reasons")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button")); // collapse
    expect(screen.queryByText("Suspicion Reasons")).not.toBeInTheDocument();
  });

  it("handles alert with empty suspicion reasons", () => {
    render(<AlertCard alert={makeAlert({ suspicion_reasons: [] })} />);
    fireEvent.click(screen.getByRole("button"));
    // Should not show reasons section
    expect(screen.queryByText("Suspicion Reasons")).not.toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// WebSocket reconnect logic test
// ---------------------------------------------------------------------------

describe("useWsReconnect", () => {
  let mockWs: { onopen: (() => void) | null; onclose: (() => void) | null; close: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.useFakeTimers();
    mockWs = { onopen: null, onclose: null, close: vi.fn() };

    vi.stubGlobal("WebSocket", vi.fn().mockImplementation(() => {
      const ws = {
        onopen: null as (() => void) | null,
        onmessage: null as ((e: MessageEvent) => void) | null,
        onclose: null as (() => void) | null,
        onerror: null as (() => void) | null,
        close: vi.fn(),
      };
      mockWs = ws;
      return ws;
    }));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("reconnects with exponential backoff", () => {
    const onMessage = vi.fn();
    const statusChanges: WsConnectionStatus[] = [];

    function TestComponent() {
      useWsReconnect("ws://test/ws", onMessage, (s) => statusChanges.push(s));
      return null;
    }

    render(<TestComponent />);

    // First connection attempt
    expect(statusChanges).toContain("reconnecting");

    // Simulate successful open then close
    act(() => { mockWs.onopen?.(); });
    expect(statusChanges).toContain("connected");

    act(() => { mockWs.onclose?.(); });
    expect(statusChanges).toContain("disconnected");

    // After 1s (initial backoff), should try to reconnect
    act(() => { vi.advanceTimersByTime(1000); });
    // Second connection
    expect(WebSocket).toHaveBeenCalledTimes(2);

    // Close again, backoff doubles to 2s
    act(() => { mockWs.onclose?.(); });
    act(() => { vi.advanceTimersByTime(1500); });
    expect(WebSocket).toHaveBeenCalledTimes(2); // not yet
    act(() => { vi.advanceTimersByTime(500); });
    expect(WebSocket).toHaveBeenCalledTimes(3); // now at 2s
  });
});

// ---------------------------------------------------------------------------
// AlertHistoryTable tests (filter + pagination)
// ---------------------------------------------------------------------------

describe("AlertHistoryTable", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows loading skeleton then renders alerts", async () => {
    const alerts = [
      makeAlert(),
      makeAlert({ tx_hash: "0xaabbcc", block_number: 18500001, summary: "Reentrancy on Compound" }),
    ];

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => makeQueryResult(alerts, 2),
    }));

    render(<AlertHistoryTable />);

    // Wait for data to load
    await waitFor(() => {
      expect(screen.getByText("Possible flash loan attack on Uniswap V3")).toBeInTheDocument();
      expect(screen.getByText("Reentrancy on Compound")).toBeInTheDocument();
    });

    expect(screen.getByText("Page 1 of 1")).toBeInTheDocument();
  });

  it("shows empty state when no results", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => makeQueryResult([], 0),
    }));

    render(<AlertHistoryTable />);

    await waitFor(() => {
      expect(screen.getByText("No alerts found")).toBeInTheDocument();
    });
  });

  it("applies priority filter", async () => {
    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => makeQueryResult([], 0),
    });
    vi.stubGlobal("fetch", fetchSpy);

    render(<AlertHistoryTable />);

    await waitFor(() => {
      expect(fetchSpy).toHaveBeenCalled();
    });

    // Change priority filter
    fireEvent.change(screen.getByLabelText("Priority filter"), {
      target: { value: "Critical" },
    });

    await waitFor(() => {
      const lastCall = fetchSpy.mock.calls[fetchSpy.mock.calls.length - 1][0] as string;
      expect(lastCall).toContain("priority=Critical");
    });
  });

  it("handles pagination", async () => {
    const alerts = Array.from({ length: 20 }, (_, i) =>
      makeAlert({ block_number: 18500000 + i })
    );

    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => makeQueryResult(alerts, 45),
    });
    vi.stubGlobal("fetch", fetchSpy);

    render(<AlertHistoryTable />);

    await waitFor(() => {
      expect(screen.getByText("Page 1 of 3")).toBeInTheDocument();
    });

    // Click Next
    fireEvent.click(screen.getByText("Next"));

    await waitFor(() => {
      const lastCall = fetchSpy.mock.calls[fetchSpy.mock.calls.length - 1][0] as string;
      expect(lastCall).toContain("page=2");
    });

    // Previous button should be enabled
    expect(screen.getByText("Previous")).not.toBeDisabled();
  });
});

// ---------------------------------------------------------------------------
// SentinelMetricsPanel tests
// ---------------------------------------------------------------------------

describe("SentinelMetricsPanel", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders metrics from API", async () => {
    const snapshot: SentinelMetricsSnapshot = {
      blocks_scanned: 1234,
      txs_scanned: 56789,
      txs_flagged: 42,
      alerts_emitted: 7,
    };

    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => snapshot,
    }));

    render(<SentinelMetricsPanel />);

    await waitFor(() => {
      expect(screen.getByText("1,234")).toBeInTheDocument();
      expect(screen.getByText("56,789")).toBeInTheDocument();
      expect(screen.getByText("42")).toBeInTheDocument();
      expect(screen.getByText("7")).toBeInTheDocument();
      expect(screen.getByText("0.07%")).toBeInTheDocument();
    });
  });

  it("shows error state when API fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));

    render(<SentinelMetricsPanel />);

    await waitFor(() => {
      expect(screen.getByText("Unable to load metrics")).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// AlertFeed tests
// ---------------------------------------------------------------------------

describe("AlertFeed", () => {
  beforeEach(() => {
    vi.stubGlobal("WebSocket", vi.fn().mockImplementation(() => ({
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      close: vi.fn(),
    })));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders empty state initially", () => {
    render(<AlertFeed wsUrl="ws://test/ws" />);
    expect(screen.getByText("Live Alert Feed")).toBeInTheDocument();
    expect(screen.getByText("Waiting for alerts...")).toBeInTheDocument();
  });

  it("shows connection status indicator", () => {
    render(<AlertFeed wsUrl="ws://test/ws" />);
    // Initially reconnecting
    expect(screen.getByText(/Reconnecting|Disconnected|Connected/)).toBeInTheDocument();
  });
});
