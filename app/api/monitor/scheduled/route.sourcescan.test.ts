import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const admitAuditsMock = vi.fn();
const admitSourcesMock = vi.fn();
const admitDependenciesMock = vi.fn();
const admitMonitoringMock = vi.fn();
const admitIntelligenceMock = vi.fn();
const runGraphReasonerMock = vi.fn();
const collectTrafficFactsMock = vi.fn();
const saveFactsMock = vi.fn();
const sendWeeklyDigestMock = vi.fn();
const pruneOldTrafficMock = vi.fn();
const purgeIntelligenceMock = vi.fn();
const pruneSnapshotsMock = vi.fn();
const enqueueJobMock = vi.fn();
const supersedeMock = vi.fn();
const supersedeScheduledMock = vi.fn();
const syncSnippetMock = vi.fn();

let tableRows: Record<string, unknown[]> = {};

vi.mock("@/lib/jobs/scheduler", () => ({
  admitDueRepositoryAudits: admitAuditsMock,
  admitDueRepositorySourceScans: admitSourcesMock,
  admitDueRepositoryDependencyChecks: admitDependenciesMock,
  admitDueMonitoringPasses: admitMonitoringMock,
  admitDueIntelligenceScans: admitIntelligenceMock,
}));
vi.mock("@/lib/jobs/queue", () => ({ enqueueJob: enqueueJobMock, supersedeStaleAudits: supersedeMock, supersedeStaleScheduledJobs: supersedeScheduledMock }));
vi.mock("@/lib/traffic/prune", () => ({ pruneOldTraffic: pruneOldTrafficMock }));
vi.mock("@/lib/intelligence/retention", () => ({ purgeIntelligenceTasks: purgeIntelligenceMock }));
vi.mock("@/lib/monitoring/snapshotRetention", () => ({ pruneProviderSnapshots: pruneSnapshotsMock }));
const freshnessMock = vi.fn();
vi.mock("@/lib/monitoring/freshness", () => ({ admitFreshnessRechecks: freshnessMock }));
vi.mock("@/lib/graph/graphRun", () => ({
  runGraphReasoner: runGraphReasonerMock,
  saveFacts: saveFactsMock,
}));
vi.mock("@/lib/traffic/graphFacts", () => ({ collectTrafficFacts: collectTrafficFactsMock }));
vi.mock("@/lib/traffic/snippetObservations", () => ({ syncSnippetObservations: syncSnippetMock }));
vi.mock("@/lib/monitoring/digest", () => ({ sendWeeklyDigest: sendWeeklyDigestMock }));

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      const rows = tableRows[table] ?? [];
      const chain: Record<string, unknown> = {};
      const self = () => chain;
      chain.select = self;
      chain.eq = self;
      chain.not = self;
      chain.lt = self;
      chain.or = self;
      chain.order = self;
      chain.limit = self;
      chain.then = (resolve: (value: unknown) => unknown) => resolve({ data: rows, error: null });
      chain.update = () => {
        const update: Record<string, unknown> = {};
        update.eq = () => update;
        update.not = () => update;
        update.lt = () => update;
        update.select = () => Promise.resolve({ data: [], error: null });
        update.then = (resolve: (value: unknown) => unknown) => resolve({ data: [], error: null });
        return update;
      };
      return chain;
    },
  }),
}));

const { GET } = await import("./route");

function request(secret = "cron-dummy") {
  return new NextRequest("https://shiplock.dev/api/monitor/scheduled", {
    headers: { authorization: `Bearer ${secret}` },
  });
}

describe("GET /api/monitor/scheduled — durable source admission", () => {
  beforeEach(() => {
    supersedeMock.mockReset().mockResolvedValue(5);
    supersedeScheduledMock.mockReset().mockResolvedValue(7);
    vi.clearAllMocks();
    tableRows = {};
    admitAuditsMock.mockResolvedValue({ eligible: 3, admitted: 2, failed: 1, limited: false });
    admitSourcesMock.mockResolvedValue({ eligible: 4, admitted: 4, failed: 0, limited: true });
    admitDependenciesMock.mockResolvedValue({ eligible: 2, admitted: 2, failed: 0, limited: false });
    admitMonitoringMock.mockResolvedValue({ eligible: 5, admitted: 4, failed: 1, limited: false });
    admitIntelligenceMock.mockResolvedValue({ eligible: 1, admitted: 1, failed: 0, limited: false });
    runGraphReasonerMock.mockResolvedValue({ total: 0, newCount: 0, resolvedCount: 0 });
    collectTrafficFactsMock.mockResolvedValue([]);
    sendWeeklyDigestMock.mockResolvedValue(false);
    pruneOldTrafficMock.mockResolvedValue({ ok: true });
    purgeIntelligenceMock.mockResolvedValue({ ok: true, purged: 2 });
    pruneSnapshotsMock.mockResolvedValue({ ok: true, pruned: 5 });
    freshnessMock.mockResolvedValue({ admitted: 3, failed: 0 });
    enqueueJobMock.mockResolvedValue("11111111-1111-4111-8111-111111111111");
    syncSnippetMock.mockResolvedValue(1);
  });

  // X2 (2026-10-12): each selected repository's snippet traffic is written as
  // observations before its graph job, so the rate-limit offer sees it; one
  // repository's failure never stops the others or the graph admission.
  it("records each repository's snippet traffic before its graph job, failing soft", async () => {
    tableRows = { user_profiles: [{ id: "u1" }], repositories: [{ id: "r1" }, { id: "r2" }] };
    syncSnippetMock.mockRejectedValueOnce(new Error("snippet observations not written: invalid traffic observations"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const body = await (await GET(request())).json();
      expect(syncSnippetMock).toHaveBeenCalledWith("u1", "r1");
      expect(syncSnippetMock).toHaveBeenCalledWith("u1", "r2");
      expect(enqueueJobMock).toHaveBeenCalledWith("u1", "r1", "graph", expect.any(String));
      expect(enqueueJobMock).toHaveBeenCalledWith("u1", "r2", "graph", expect.any(String));
      expect(body).toMatchObject({ snippetObservationsFailed: 1, graphJobsAdmitted: 2 });
    } finally { log.mockRestore(); }
  });

  it("authenticates before any admission or legacy side effect", async () => {
    const response = await GET(request("wrong"));
    expect(response.status).toBe(401);
    expect(admitAuditsMock).not.toHaveBeenCalled();
    expect(admitSourcesMock).not.toHaveBeenCalled();
    expect(admitDependenciesMock).not.toHaveBeenCalled();
    expect(admitMonitoringMock).not.toHaveBeenCalled();
  });

  it("admits bounded audit and source batches before legacy scheduled work", async () => {
    const response = await GET(request());
    const body = await response.json();

    expect(admitAuditsMock).toHaveBeenCalledWith(expect.any(Date), 1_000);
    expect(admitSourcesMock).toHaveBeenCalledWith(expect.any(Date), 1_000);
    expect(admitDependenciesMock).toHaveBeenCalledWith(expect.any(Date), 1_000);
    expect(admitMonitoringMock).toHaveBeenCalledWith("scheduled_48h",expect.any(Date),1_000);
    expect(admitIntelligenceMock).toHaveBeenCalledWith(expect.any(Date), 1_000);
    expect(body).toMatchObject({
      intelligenceJobsAdmitted: 1,
      intelligenceAdmissionsFailed: 0,
      intelligenceAdmissionLimited: false,
      auditsEligible: 3,
      auditsAdmitted: 2,
      auditAdmissionsFailed: 1,
      sourceJobsAdmitted: 4,
      sourceAdmissionsFailed: 0,
      sourceAdmissionLimited: true,
      dependencyJobsAdmitted: 2,
      dependencyAdmissionsFailed: 0,
      dependencyAdmissionLimited: false,
      monitorJobsAdmitted: 4,
      monitorAdmissionsFailed: 1,
      monitorAdmissionLimited: false,
    });
  });

  // 097 (2026-10-01): after the day's audits are admitted, older queued audits
  // of the same repository are replaced; a failure here never fails the pass.
  it("replaces stale queued audits after admission and reports how many", async () => {
    const body = await (await GET(request())).json();
    expect(supersedeMock).toHaveBeenCalledOnce();
    expect(supersedeMock.mock.invocationCallOrder[0]).toBeGreaterThan(admitAuditsMock.mock.invocationCallOrder[0]);
    expect(body.staleAuditsReplaced).toBe(5);
    supersedeMock.mockRejectedValue(new Error("db"));
    expect((await GET(request())).status).toBe(200);
  });

  // 108: after every admission, including the graph jobs at the end, older
  // queued scheduled copies are replaced; a failure never fails the pass.
  it("replaces stale scheduled copies after the graph admission and reports how many", async () => {
    const body = await (await GET(request())).json();
    expect(supersedeScheduledMock).toHaveBeenCalledOnce();
    const graphAdmissions = enqueueJobMock.mock.invocationCallOrder;
    if (graphAdmissions.length > 0) expect(supersedeScheduledMock.mock.invocationCallOrder[0]).toBeGreaterThan(Math.max(...graphAdmissions));
    expect(body.staleScheduledReplaced).toBe(7);
    supersedeScheduledMock.mockRejectedValue(new Error("db"));
    expect((await GET(request())).status).toBe(200);
  });

  it("returns a retryable failure before side effects when either admission fails", async () => {
    admitSourcesMock.mockRejectedValue(new Error("private storage detail"));
    const response = await GET(request());

    expect(response.status).toBe(503);
    expect(admitMonitoringMock).toHaveBeenCalledOnce();
    expect(runGraphReasonerMock).not.toHaveBeenCalled();
    expect(sendWeeklyDigestMock).not.toHaveBeenCalled();
  });

  it("does not perform GitHub collection inside the cron request", async () => {
    tableRows = { user_profiles: [{ id: "u1", github_installation_id: 42 }] };
    const response = await GET(request());
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.sourceJobsAdmitted).toBe(4);
    expect(admitSourcesMock).toHaveBeenCalledOnce();
  });

  it("purges expired intelligence tasks on the daily pass", async () => {
    const body = await (await GET(request())).json();
    expect(purgeIntelligenceMock).toHaveBeenCalledOnce();
    expect(pruneSnapshotsMock).toHaveBeenCalledOnce();
    expect(body).toMatchObject({ intelligencePurged: 2, providerSnapshotsPruned: 5, freshnessAdmitted: 3, freshnessFailed: 0 });
  });
});
