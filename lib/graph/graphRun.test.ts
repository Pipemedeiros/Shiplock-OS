import { describe, it, expect, vi, beforeEach } from "vitest";

const selectFactsMock = vi.fn();
const maybeSingleMock = vi.fn();
const upsertMock = vi.fn();
const findingsSelectMock = vi.fn();
const insertMock = vi.fn();
const updateInMock = vi.fn();
const updateSpy = vi.fn();
const repositoriesSelectMock = vi.fn();
const findingFilterSpy = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "graph_facts") {
        return {
          select: () => ({
            eq: () => ({
              // loadGraphInput: .eq(user).then  |  saveFacts merge: .eq().eq().maybeSingle()
              then: (res: (v: unknown) => unknown) => Promise.resolve(selectFactsMock()).then(res),
              eq: () => ({ maybeSingle: maybeSingleMock }),
            }),
          }),
          upsert: upsertMock,
        };
      }
      if (table === "repositories") {
        const query = {
          eq: () => query,
          then: (resolve: (value: unknown) => unknown, reject: (error: unknown) => unknown) =>
            Promise.resolve(repositoriesSelectMock()).then(resolve, reject),
        };
        return { select: () => query };
      }
      if (table === "deep_findings") {
        const selectQuery = {
          eq: (field: string, value: unknown) => { findingFilterSpy("select", field, value); return selectQuery; },
          is: (field: string, value: unknown) => {
            findingFilterSpy("select", field, value);
            return field === "archived_at" ? findingsSelectMock() : selectQuery;
          },
        };
        return {
          select: () => selectQuery,
          insert: insertMock,
          update: (patch: unknown) => {
            updateSpy(patch);
            const updateQuery = {
              eq: (field: string, value: unknown) => { findingFilterSpy("update", field, value); return updateQuery; },
              is: (field: string, value: unknown) => { findingFilterSpy("update", field, value); return updateQuery; },
              in: updateInMock,
            };
            return updateQuery;
          },
        };
      }
      throw new Error(`unexpected table ${table}`);
    },
  }),
}));

const { runGraphReasoner: runStoredGraphReasoner, persistGraphPaths, saveFacts, loadGraphInput, canRetireGraphFindings } = await import("./graphRun");

// Persistence tests supply trusted synthetic inputs directly. These fixtures
// deliberately do NOT stand in for production stored-fact admission, which is
// tested below through the actual loader and scheduled reasoner entry point.
async function runGraphReasoner(userId: string) {
  const { data, error } = await selectFactsMock();
  if (error) throw new Error("Graph facts could not be read");
  const input = Object.assign({}, ...(data ?? []).filter((row: { collector: string }) =>
    row.collector === "source" || row.collector === "db").map((row: { facts: object }) => row.facts));
  return persistGraphPaths(userId, input);
}

const routeFact = {
  path: "/api/invoices",
  file: "app/api/invoices/route.ts",
  methods: ["GET"],
  tables: ["invoices"],
  authenticated: false,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  ownershipReadable: true,
  ownershipGap: null,
  serviceRoleReadable: true,
  machineGateReadable: true,
  machineGateGap: null,
  via: [],
};

const vulnerableFacts = [
  { collector: "source", facts: { routes: [routeFact] } },
  { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: false }], policies: [] } },
];

describe("saveFacts", () => {
  beforeEach(() => {
    upsertMock.mockReset().mockResolvedValue({ error: null });
    maybeSingleMock.mockReset().mockResolvedValue({ data: null });
  });

  it("writes facts for a collector", async () => {
    await saveFacts("u1", "source", { routes: [routeFact] });
    const row = upsertMock.mock.calls[0][0];
    expect(row.user_id).toBe("u1");
    expect(row.collector).toBe("source");
    expect(row.facts._evidence).toMatchObject({ version: 1, fields: {
      routes: { recordedAt: row.updated_at, completeness: "unknown" },
    } });
  });

  it("preserves the age and completeness of untouched fields", async () => {
    const old = { recordedAt: "2026-01-01T00:00:00.000Z", completeness: "partial", reason: "limited" };
    maybeSingleMock.mockResolvedValue({ data: { facts: {
      policies: [], _evidence: { version: 1, fields: { policies: old } },
    } } });
    await saveFacts("u1", "db", { scanTables: [] }, { merge: true });
    const evidence = upsertMock.mock.calls[0][0].facts._evidence.fields;
    expect(evidence.policies).toEqual(old);
    expect(evidence.scanTables.completeness).toBe("unknown");
    expect(evidence.scanTables.recordedAt).not.toBe(old.recordedAt);
  });

  it("does not fabricate metadata for retained legacy fields", async () => {
    maybeSingleMock.mockResolvedValue({ data: { facts: { policies: [] } } });
    await saveFacts("u1", "db", { scanTables: [] }, { merge: true });
    expect(upsertMock.mock.calls[0][0].facts._evidence.fields.policies).toBeUndefined();
  });

  it("records a bounded collector's partial status and reason", async () => {
    await saveFacts("u1", "source", { routes: [], repositories: [] }, { completeness: "partial", reason: "file cap" });
    expect(upsertMock.mock.calls[0][0].facts._evidence.fields.routes).toMatchObject({
      completeness: "partial", reason: "file cap",
    });
    expect(upsertMock.mock.calls[0][0].facts.repositories).toEqual([]);
    expect(upsertMock.mock.calls[0][0].facts._evidence.fields.repositories).toMatchObject({
      completeness: "partial", reason: "file cap",
      recordedAt: upsertMock.mock.calls[0][0].updated_at,
    });
  });

  it("replaces metadata along with a wholesale snapshot", async () => {
    maybeSingleMock.mockResolvedValue({ data: { facts: { policies: [], _evidence: { version: 1, fields: { policies: {} } } } } });
    await saveFacts("u1", "db", { scanTables: [] });
    expect(Object.keys(upsertMock.mock.calls[0][0].facts._evidence.fields)).toEqual(["scanTables"]);
  });

  it("does not overwrite stored facts after a failed merge read", async () => {
    maybeSingleMock.mockResolvedValue({ data: null, error: { message: "read unavailable" } });
    await expect(saveFacts("u1", "db", { scanTables: [] }, { merge: true })).resolves.toBeUndefined();
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("reports returned write errors while preserving the fail-soft caller contract", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      upsertMock.mockResolvedValue({ error: { message: "write unavailable" } });
      await expect(saveFacts("u1", "source", { routes: [] })).resolves.toBeUndefined();
      expect(log).toHaveBeenCalledWith(expect.stringContaining("failed to save source"), expect.stringContaining("write unavailable"));
    } finally { log.mockRestore(); }
  });

  // The db collector has two independent producers on different schedules.
  // Without merge, whichever ran last would erase the other's facts and the
  // reasoner would quietly stop producing paths.
  it("merges into existing facts rather than replacing them", async () => {
    maybeSingleMock.mockResolvedValue({ data: { facts: { policies: [{ tablename: "x" }] } } });
    await saveFacts("u1", "db", { scanTables: [{ name: "invoices", rlsEnabled: false }] }, { merge: true });
    const written = upsertMock.mock.calls[0][0].facts;
    expect(written.policies).toHaveLength(1);
    expect(written.scanTables).toHaveLength(1);
  });

  it("overwrites the same key on merge, keeping the newest value", async () => {
    maybeSingleMock.mockResolvedValue({ data: { facts: { scanTables: [{ name: "old", rlsEnabled: true }] } } });
    await saveFacts("u1", "db", { scanTables: [{ name: "new", rlsEnabled: false }] }, { merge: true });
    expect(upsertMock.mock.calls[0][0].facts.scanTables[0].name).toBe("new");
  });

  it("replaces wholesale when merge is not requested", async () => {
    maybeSingleMock.mockResolvedValue({ data: { facts: { policies: [{ tablename: "x" }] } } });
    await saveFacts("u1", "db", { scanTables: [] });
    expect(upsertMock.mock.calls[0][0].facts.policies).toBeUndefined();
  });

  // A failed write must never break the monitoring pass that called it.
  it("swallows a write failure", async () => {
    upsertMock.mockRejectedValue(new Error("db down"));
    await expect(saveFacts("u1", "source", { routes: [] })).resolves.toBeUndefined();
  });
});

describe("loadGraphInput", () => {
  beforeEach(() => selectFactsMock.mockReset().mockResolvedValue({ data: [] }));

  it("never admits unbound account-wide source routes into graph correlation", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    const input = await loadGraphInput("u1");
    expect(input.routes).toBeUndefined();
    expect(canRetireGraphFindings(input)).toBe(false);
  });

  it("preserves traffic observations but excludes flat DB facts and unbound source", async () => {
    selectFactsMock.mockResolvedValue({
      data: [
        ...vulnerableFacts,
        { collector: "traffic", facts: { hotPaths: [{ path: "/login", suspiciousRequests: 5 }] } },
      ],
    });
    const input = await loadGraphInput("u1");
    expect(input.routes).toBeUndefined();
    expect(input.scanTables).toBeUndefined();
    expect(input.policies).toBeUndefined();
    expect(input.databaseEvidence).toEqual({ admission: "unknown", snapshots: {} });
    expect(input.trafficHotPaths).toHaveLength(1);
  });

  // Missing collectors are absent, never faked.
  it("leaves absent collectors undefined", async () => {
    selectFactsMock.mockResolvedValue({ data: [{ collector: "source", facts: { routes: [] } }] });
    const input = await loadGraphInput("u1");
    expect(input.routes).toBeUndefined();
    expect(input.scanTables).toBeUndefined();
  });

  it("does not treat repository provenance alone as an authorized graph join", async () => {
    selectFactsMock.mockResolvedValue({ data: [{ collector: "source", facts: {
      repositories: [{ repositoryFullName: "acme/one", routes: [routeFact] }],
    } }] });
    expect((await loadGraphInput("u1")).routes).toBeUndefined();
  });

  it("does not turn missing fields inside a collector row into empty observations", async () => {
    selectFactsMock.mockResolvedValue({ data: [
      { collector: "source", facts: { dependencies: [] } },
      { collector: "db", facts: { authConfig: null } },
    ] });
    const input = await loadGraphInput("u1");
    expect(input.routes).toBeUndefined();
    expect(input.scanTables).toBeUndefined();
  });

  it("tolerates a null read", async () => {
    selectFactsMock.mockResolvedValue({ data: null });
    expect(await loadGraphInput("u1")).toEqual({});
  });

  it("rejects a failed facts read instead of returning an empty graph", async () => {
    selectFactsMock.mockResolvedValue({ data: null, error: { message: "read failed" } });
    await expect(loadGraphInput("u1")).rejects.toThrow("Graph facts could not be read");
  });
});

describe("graph persistence with trusted synthetic inputs", () => {
  beforeEach(() => {
    selectFactsMock.mockReset().mockResolvedValue({ data: [] });
    findingsSelectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
    updateSpy.mockReset();
    repositoriesSelectMock.mockReset().mockResolvedValue({ data: [], error: null });
    findingFilterSpy.mockReset();
  });

  it("retains old paths rather than creating or resolving paths from unbound stored joins", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old-unbound-path" }] });
    const result = await runStoredGraphReasoner("u1");
    expect(result).toMatchObject({ newCount: 0, resolvedCount: 0, retainedCount: 1 });
    expect(insertMock).not.toHaveBeenCalled();
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("persists a path found by correlating two collectors", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    const result = await runGraphReasoner("u1");
    expect(result.newCount).toBe(1);
    const row = insertMock.mock.calls[0][0][0];
    expect(row.source).toBe("graph");
    expect(row.finding_id).toContain("anon_read");
    expect(row.severity).toBe("CRITICAL");
  });

  it("isolates a repository-bound path in both its read and inserted row", async () => {
    await persistGraphPaths("u1", { repositoryId: "repo-one", sourceCoverage: "partial",
      correlationScope: "repository-bound", routes: [routeFact],
      scanTables: [{ name: "invoices", rlsEnabled: false }], policies: [] });
    expect(findingFilterSpy).toHaveBeenCalledWith("select", "repository_id", "repo-one");
    expect(insertMock.mock.calls[0][0][0]).toMatchObject({ user_id: "u1", repository_id: "repo-one", source: "graph" });
  });

  it("saves replacements before retiring old paths", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    await runGraphReasoner("u1");
    expect(insertMock.mock.invocationCallOrder[0]).toBeLessThan(updateSpy.mock.invocationCallOrder[0]);
  });

  it("does not archive on a returned insert error", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    insertMock.mockResolvedValue({ error: { message: "write failed" } });
    await expect(runGraphReasoner("u1")).rejects.toThrow("could not be saved");
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("does not archive on a thrown insert failure", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    insertMock.mockRejectedValue(new Error("connection lost"));
    await expect(runGraphReasoner("u1")).rejects.toThrow("connection lost");
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("does not write when the existing findings cannot be read", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: null, error: { message: "read failed" } });
    await expect(runGraphReasoner("u1")).rejects.toThrow("could not be read");
    expect(insertMock).not.toHaveBeenCalled();
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("reports archival failure instead of claiming resolution", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    updateInMock.mockResolvedValue({ error: { message: "archive failed" } });
    await expect(runGraphReasoner("u1")).rejects.toThrow("could not be archived");
    expect(insertMock).toHaveBeenCalled();
  });

  it("does not re-insert a path that is already open", async () => {
    selectFactsMock.mockResolvedValue({ data: vulnerableFacts });
    findingsSelectMock.mockResolvedValue({
      data: [{ finding_id: "path:anon_read:/api/invoices:public.invoices" }],
    });
    const result = await runGraphReasoner("u1");
    expect(result.newCount).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
  });

  // Fixing ONE step should break the path. That is the whole idea of a path, and
  // the customer has to see it close.
  it("archives a path once one of its steps is fixed", async () => {
    selectFactsMock.mockResolvedValue({
      data: [
        { collector: "source", facts: { routes: [routeFact] } },
        { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }], policies: [] } },
      ],
    });
    findingsSelectMock.mockResolvedValue({
      data: [{ finding_id: "path:anon_read:/api/invoices:public.invoices" }],
    });
    const result = await runGraphReasoner("u1");
    expect(result.resolvedCount).toBe(1);
    expect(updateSpy.mock.calls[0][0]).toHaveProperty("archived_at");
  });

  // The dangerous case: an empty read must not look like "everything is fixed".
  it("does NOT archive anything when no collector has reported", async () => {
    selectFactsMock.mockResolvedValue({ data: [] });
    findingsSelectMock.mockResolvedValue({
      data: [{ finding_id: "path:anon_read:/api/invoices:public.invoices" }],
    });
    const result = await runGraphReasoner("u1");
    expect(result).toEqual({ total: 0, newCount: 0, resolvedCount: 0 });
    expect(updateInMock).not.toHaveBeenCalled();
  });

  it.each([
    [{ collector: "source", facts: { routes: [routeFact] } }],
    [{ collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }], policies: [] } }],
    [
      { collector: "source", facts: { routes: [routeFact] } },
      { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }] } },
    ],
    [
      { collector: "source", facts: { routes: [{ ...routeFact, identityReadable: false }] } },
      { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }], policies: [] } },
    ],
  ].map((facts) => [facts]))("retains old paths when evidence is incomplete: %j", async (facts) => {
    selectFactsMock.mockResolvedValue({ data: facts });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "previous-path" }] });
    const result = await runGraphReasoner("u1");
    expect(result.resolvedCount).toBe(0);
    expect(result.retainedCount).toBe(1);
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("still saves new paths when policy evidence is incomplete", async () => {
    selectFactsMock.mockResolvedValue({ data: [
      vulnerableFacts[0],
      { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: false }] } },
    ] });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    const result = await runGraphReasoner("u1");
    expect(result).toMatchObject({ newCount: 1, resolvedCount: 0, retainedCount: 1 });
    expect(insertMock).toHaveBeenCalled();
    expect(updateSpy).not.toHaveBeenCalled();
  });

  it("can retire paths after explicit empty source and database observations", async () => {
    selectFactsMock.mockResolvedValue({ data: [
      { collector: "source", facts: { routes: [] } },
      { collector: "db", facts: { scanTables: [], policies: [] } },
    ] });
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "old" }] });
    expect(await runGraphReasoner("u1")).toMatchObject({ resolvedCount: 1 });
    expect(updateSpy).toHaveBeenCalled();
  });

  it("writes nothing when there is nothing to change", async () => {
    selectFactsMock.mockResolvedValue({
      data: [
        { collector: "source", facts: { routes: [routeFact] } },
        {
          collector: "db",
          // `policies: []` is required for this to mean "clean". Without the key
          // the rules were never read, and an RLS-on table with unread policies
          // is unknown rather than protected — see storeProtects.
          facts: { scanTables: [{ name: "invoices", rlsEnabled: true }], policies: [] },
        },
      ],
    });
    const result = await runGraphReasoner("u1");
    expect(result.total).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
    expect(updateInMock).not.toHaveBeenCalled();
  });
});

describe("graph retirement readability", () => {
  it("cannot retire from source-only scope even if other fields appear complete", () => {
    expect(canRetireGraphFindings({ correlationScope: "source-only", sourceCoverage: "complete", routes: [], scanTables: [], policies: [] })).toBe(false);
  });
  it.each(["partial", "unknown"] as const)("cannot retire paths with %s source coverage", (sourceCoverage) => {
    expect(canRetireGraphFindings({ sourceCoverage, routes: [], scanTables: [], policies: [] })).toBe(false);
  });
  it.each(["identityReadable", "ownershipReadable", "dataReadable", "machineGateReadable", "serviceRoleReadable"] as const)(
    "requires %s", (field) => {
      expect(canRetireGraphFindings({ routes: [{ ...routeFact, [field]: false }], scanTables: [], policies: [] })).toBe(false);
    },
  );
  it("accepts explicit empty observations", () => {
    expect(canRetireGraphFindings({ routes: [], scanTables: [], policies: [] })).toBe(true);
  });
});
