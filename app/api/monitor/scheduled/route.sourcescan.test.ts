import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

// Regression test for the bug that made cross-layer correlation impossible.
//
// `runGithubScan` is the only producer of `source` graph facts, and it used to
// be reachable ONLY from the per-PR webhook. A customer who connected GitHub
// and did not open a pull request therefore never got route facts, so
// findAttackPaths never saw two surfaces, so the graph could never produce a
// finding. Verified against the live database at the time of the fix: one paid
// user with github_installation_id set, zero `source` rows, zero graph findings.
//
// These tests assert the scheduled pass now collects source facts on its own
// schedule, and that it does so BEFORE the reasoner runs — ordering is the whole
// point, since facts written after correlation would be a pass too late.

const runGithubScanMock = vi.fn();
const runGraphReasonerMock = vi.fn();
const runMonitoringPassMock = vi.fn();
const runPolicyScanMock = vi.fn();
const runZeroDayCheckMock = vi.fn();
const collectTrafficFactsMock = vi.fn();
const saveFactsMock = vi.fn();
const sendWeeklyDigestMock = vi.fn();
const pruneOldTrafficMock = vi.fn();
const updateEqMock = vi.fn();

// Records call order across mocked collectors so ordering can be asserted.
const callOrder: string[] = [];

/** Rows returned per table, settable per test. */
let tableRows: Record<string, unknown[]> = {};

vi.mock("@/lib/monitoring", () => ({ runMonitoringPass: runMonitoringPassMock }));
vi.mock("@/lib/traffic/prune", () => ({ pruneOldTraffic: pruneOldTrafficMock }));
vi.mock("@/lib/deep/supabaseMgmtRun", () => ({ runPolicyScan: runPolicyScanMock }));
vi.mock("@/lib/deep/githubRun", () => ({ runGithubScan: runGithubScanMock }));
vi.mock("@/lib/graph/graphRun", () => ({
  runGraphReasoner: runGraphReasonerMock,
  saveFacts: saveFactsMock,
}));
vi.mock("@/lib/traffic/graphFacts", () => ({ collectTrafficFacts: collectTrafficFactsMock }));
vi.mock("@/lib/runtime/zeroDay", () => ({ runZeroDayCheck: runZeroDayCheckMock }));
vi.mock("@/lib/monitoring/digest", () => ({ sendWeeklyDigest: sendWeeklyDigestMock }));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      // Every select chain in this route ends in an awaitable thenable; model it
      // as a promise-like that resolves to the rows configured for that table.
      const rows = tableRows[table] ?? [];
      const chain: Record<string, unknown> = {};
      const self = () => chain;
      chain.select = self;
      chain.eq = self;
      chain.not = self;
      chain.lt = self;
      chain.or = self;
      chain.order = self;
      chain.then = (resolve: (v: unknown) => unknown) => resolve({ data: rows, error: null });
      // update() chains vary in length across call sites (a plain
      // `.update().eq()` for the scan stamp, `.update().eq().not().lt().select()`
      // for the prepaid-expiry sweep), so make every link both chainable and
      // awaitable rather than modelling each shape separately.
      chain.update = () => {
        const upd: Record<string, unknown> = {};
        const link = (...args: unknown[]) => {
          if (args.length > 0) updateEqMock(table, ...args);
          return upd;
        };
        upd.eq = link;
        upd.not = () => upd;
        upd.lt = () => upd;
        upd.select = () => Promise.resolve({ data: [], error: null });
        upd.then = (resolve: (v: unknown) => unknown) => resolve({ data: [], error: null });
        return upd;
      };
      return chain;
    },
  }),
}));

const { GET } = await import("./route");

function req() {
  return new NextRequest("https://shiplock.dev/api/monitor/scheduled", {
    headers: { authorization: "Bearer cron-dummy" },
  });
}

describe("GET /api/monitor/scheduled — source facts land without PR activity", () => {
  beforeEach(() => {
    callOrder.length = 0;
    tableRows = {};
    runGithubScanMock.mockReset().mockImplementation(async () => {
      callOrder.push("github");
      return { total: 0, newCount: 0, resolvedCount: 0 };
    });
    runGraphReasonerMock.mockReset().mockImplementation(async () => {
      callOrder.push("reasoner");
      return { total: 0, newCount: 0, resolvedCount: 0 };
    });
    runMonitoringPassMock.mockReset().mockResolvedValue({ newFindingsCount: 0 });
    runPolicyScanMock.mockReset().mockResolvedValue({ ok: true });
    runZeroDayCheckMock.mockReset().mockResolvedValue(undefined);
    collectTrafficFactsMock.mockReset().mockResolvedValue([]);
    saveFactsMock.mockReset();
    sendWeeklyDigestMock.mockReset().mockResolvedValue(false);
    pruneOldTrafficMock.mockReset().mockResolvedValue({ ok: true });
    updateEqMock.mockReset();
  });

  it("401s without the cron secret, before doing any work", async () => {
    const res = await GET(
      new NextRequest("https://shiplock.dev/api/monitor/scheduled", {
        headers: { authorization: "Bearer wrong" },
      })
    );
    expect(res.status).toBe(401);
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("runs the source scan for a GitHub-connected paid user who has opened no PRs", async () => {
    tableRows = { user_profiles: [{ id: "u1", github_installation_id: 42 }] };

    const res = await GET(req());
    const body = await res.json();

    expect(runGithubScanMock).toHaveBeenCalledWith("u1", 42);
    expect(body.sourceScanned).toBe(1);
  });

  it("stamps last_source_scan_at so the PR webhook and this pass share one notion of recency", async () => {
    tableRows = { user_profiles: [{ id: "u1", github_installation_id: 42 }] };

    await GET(req());

    expect(updateEqMock).toHaveBeenCalledWith("user_profiles", "id", "u1");
  });

  it("collects source facts BEFORE running the reasoner — facts written after correlation are a pass too late", async () => {
    tableRows = { user_profiles: [{ id: "u1", github_installation_id: 42 }] };

    await GET(req());

    const firstGithub = callOrder.indexOf("github");
    const firstReasoner = callOrder.indexOf("reasoner");
    expect(firstGithub).toBeGreaterThanOrEqual(0);
    expect(firstReasoner).toBeGreaterThanOrEqual(0);
    expect(firstGithub).toBeLessThan(firstReasoner);
  });

  it("a failing source scan does not stop the reasoner or the rest of the pass", async () => {
    tableRows = { user_profiles: [{ id: "u1", github_installation_id: 42 }] };
    runGithubScanMock.mockRejectedValue(new Error("GitHub is down"));

    const res = await GET(req());
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.sourceScanned).toBe(0);
    expect(runGraphReasonerMock).toHaveBeenCalled();
  });
});
