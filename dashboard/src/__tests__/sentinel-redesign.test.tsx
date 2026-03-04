import { describe, it, expect, afterEach, vi, beforeEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import SentinelHeader from "@/components/sentinel/SentinelHeader";
import { AlertPriorityBadge } from "@/components/sentinel/AlertPriorityBadge";
import { AlertCard } from "@/components/sentinel/AlertCard";
import { SentinelMetricsPanel } from "@/components/sentinel/SentinelMetricsPanel";
import EmptyState from "@/components/sentinel/EmptyState";
import SuspicionScoreGauge from "@/components/sentinel/SuspicionScoreGauge";
import type { SentinelAlert, SentinelMetricsSnapshot } from "@/types/sentinel";

afterEach(cleanup);

// ---------------------------------------------------------------------------
// Test data helpers
// ---------------------------------------------------------------------------

function makeAlert(overrides?: Partial<SentinelAlert>): SentinelAlert {
  return {
    block_number: 19234567,
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

// ---------------------------------------------------------------------------
// SentinelHeader tests
// ---------------------------------------------------------------------------

describe("SentinelHeader (sentinel/)", () => {
  it("renders Dashboard and Alert History nav links", () => {
    render(<SentinelHeader currentPath="/sentinel" />);
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Alert History")).toBeInTheDocument();
  });

  it("marks Dashboard link as active when on /sentinel", () => {
    render(<SentinelHeader currentPath="/sentinel" />);
    const dashboardLink = screen.getByText("Dashboard").closest("a");
    expect(dashboardLink?.className).toContain("sentinel-primary");
  });

  it("marks Alert History link as active when on /sentinel/history", () => {
    render(<SentinelHeader currentPath="/sentinel/history" />);
    const historyLink = screen.getByText("Alert History").closest("a");
    expect(historyLink?.className).toContain("sentinel-primary");
  });

  it("marks Dashboard as inactive when on /sentinel/history", () => {
    render(<SentinelHeader currentPath="/sentinel/history" />);
    const dashboardLink = screen.getByText("Dashboard").closest("a");
    expect(dashboardLink?.className).not.toContain("font-semibold");
    expect(dashboardLink?.className).toContain("text-slate-400");
  });

  it("renders Argus Sentinel logo", () => {
    render(<SentinelHeader currentPath="/sentinel" />);
    expect(screen.getByText("Argus Sentinel")).toBeInTheDocument();
  });

  it("shows connected status indicator", () => {
    render(<SentinelHeader currentPath="/sentinel" />);
    expect(screen.getByText("WebSocket: Connected")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// AlertPriorityBadge (sentinel/) tests
// ---------------------------------------------------------------------------

describe("AlertPriorityBadge (sentinel/)", () => {
  it("renders Medium priority", () => {
    render(<AlertPriorityBadge priority="Medium" />);
    expect(screen.getByText("Medium")).toBeInTheDocument();
  });

  it("renders High priority", () => {
    render(<AlertPriorityBadge priority="High" />);
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("renders Critical priority", () => {
    render(<AlertPriorityBadge priority="Critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("applies sentinel-critical style for Critical", () => {
    render(<AlertPriorityBadge priority="Critical" />);
    const badge = screen.getByText("Critical");
    expect(badge.className).toContain("sentinel-critical");
  });

  it("applies sentinel-medium style for Medium", () => {
    render(<AlertPriorityBadge priority="Medium" />);
    const badge = screen.getByText("Medium");
    expect(badge.className).toContain("sentinel-medium");
  });

  it("applies sentinel-high style for High", () => {
    render(<AlertPriorityBadge priority="High" />);
    const badge = screen.getByText("High");
    expect(badge.className).toContain("sentinel-high");
  });
});

// ---------------------------------------------------------------------------
// AlertCard (sentinel/) tests
// ---------------------------------------------------------------------------

describe("AlertCard (sentinel/)", () => {
  it("renders priority badge, truncated hash, block number, and summary", () => {
    render(<AlertCard alert={makeAlert()} />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText(/TX:.*0xdead/)).toBeInTheDocument();
    expect(screen.getByText(/Block: 19234567/)).toBeInTheDocument();
    expect(screen.getByText("Possible flash loan attack on Uniswap V3")).toBeInTheDocument();
  });

  it("renders score column with score value", () => {
    render(<AlertCard alert={makeAlert()} />);
    expect(screen.getByText("0.75")).toBeInTheDocument();
    expect(screen.getByText("Score")).toBeInTheDocument();
  });

  it("renders suspicion reason category", () => {
    render(<AlertCard alert={makeAlert()} />);
    expect(screen.getByText("FlashLoanSignature")).toBeInTheDocument();
  });

  it("renders schedule icon text", () => {
    render(<AlertCard alert={makeAlert()} />);
    expect(screen.getByText("Just now")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// SentinelMetricsPanel (sentinel/) tests
// ---------------------------------------------------------------------------

describe("SentinelMetricsPanel (sentinel/)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders 5 metric cards after fetch", async () => {
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

    await screen.findByText("1,234");
    expect(screen.getByText("56,789")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("0.0740%")).toBeInTheDocument();
  });

  it("shows error state on fetch failure", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network error")));

    render(<SentinelMetricsPanel />);

    await screen.findByText("Unable to load metrics");
  });
});

// ---------------------------------------------------------------------------
// EmptyState tests
// ---------------------------------------------------------------------------

describe("EmptyState", () => {
  it("renders Getting Started title and 3 steps", () => {
    render(<EmptyState status="connecting" />);
    expect(screen.getByText("Getting Started")).toBeInTheDocument();
    expect(screen.getByText("Configure Your RPC Endpoint")).toBeInTheDocument();
    expect(screen.getByText("Start the Sentinel Service")).toBeInTheDocument();
    expect(screen.getByText("Monitor Live Alerts")).toBeInTheDocument();
  });

  it("renders Argus Sentinel title", () => {
    render(<EmptyState status="connecting" />);
    expect(screen.getByText("Argus Sentinel")).toBeInTheDocument();
  });

  it("shows Connecting... status when connecting", () => {
    render(<EmptyState status="connecting" />);
    expect(screen.getByText("Connecting...")).toBeInTheDocument();
  });

  it("shows Connected status when connected", () => {
    render(<EmptyState status="connected" />);
    expect(screen.getByText("Connected")).toBeInTheDocument();
  });

  it("shows Disconnected status when disconnected", () => {
    render(<EmptyState status="disconnected" />);
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("renders View Documentation, Configure Sentinel, and Check Connection buttons", () => {
    render(<EmptyState status="connected" />);
    expect(screen.getByText("View Documentation")).toBeInTheDocument();
    expect(screen.getByText("Configure Sentinel")).toBeInTheDocument();
    expect(screen.getByText("Check Connection")).toBeInTheDocument();
  });

  it("renders subtitle Ethereum Attack Detection Monitor", () => {
    render(<EmptyState status="connected" />);
    expect(screen.getByText("Ethereum Attack Detection Monitor")).toBeInTheDocument();
  });

  it("renders footer with Powered by Argus v0.2.0", () => {
    render(<EmptyState status="connected" />);
    expect(screen.getByText("Powered by Argus v0.2.0")).toBeInTheDocument();
    expect(screen.getByText("SECURE / VIGILANT / ANOMALY-AWARE")).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// SuspicionScoreGauge tests
// ---------------------------------------------------------------------------

describe("SuspicionScoreGauge", () => {
  it("renders score value", () => {
    render(<SuspicionScoreGauge score={0.87} />);
    expect(screen.getByText("0.87")).toBeInTheDocument();
  });

  it("shows Critical Risk label for high scores", () => {
    render(<SuspicionScoreGauge score={0.87} />);
    expect(screen.getByText("Critical Risk")).toBeInTheDocument();
  });

  it("shows High Risk label for medium-high scores", () => {
    render(<SuspicionScoreGauge score={0.6} />);
    expect(screen.getByText("High Risk")).toBeInTheDocument();
  });

  it("shows Medium Risk label for low scores", () => {
    render(<SuspicionScoreGauge score={0.3} />);
    expect(screen.getByText("Medium Risk")).toBeInTheDocument();
  });

  it("renders Suspicion Score label", () => {
    render(<SuspicionScoreGauge score={0.5} />);
    expect(screen.getByText("Suspicion Score")).toBeInTheDocument();
  });

  it("applies sentinel-critical color class for score >= 0.75", () => {
    render(<SuspicionScoreGauge score={0.87} />);
    const scoreEl = screen.getByText("0.87");
    expect(scoreEl.className).toContain("sentinel-critical");
  });

  it("applies sentinel-high color class for 0.50 <= score < 0.75", () => {
    render(<SuspicionScoreGauge score={0.6} />);
    const scoreEl = screen.getByText("0.60");
    expect(scoreEl.className).toContain("sentinel-high");
  });

  it("clamps score to 0-1 range", () => {
    render(<SuspicionScoreGauge score={1.5} />);
    // The clamped score element has a bold class; axis labels do not
    const scoreEl = screen.getAllByText("1.00").find(
      (el) => el.className.includes("font-bold"),
    );
    expect(scoreEl).toBeInTheDocument();
  });
});
