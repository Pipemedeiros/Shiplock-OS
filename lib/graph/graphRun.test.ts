import { describe, it, expect, vi, beforeEach } from "vitest";

const selectFactsMock = vi.fn();
const maybeSingleMock = vi.fn();
const upsertMock = vi.fn();
const findingsSelectMock = vi.fn();
const insertMock = vi.fn();
const updateInMock = vi.fn();
const updateSpy = vi.fn();

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
      if (table === "deep_findings") {
        return {
          select: () => ({ eq: () => ({ eq: () => ({ is: findingsSelectMock }) }) }),
          insert: insertMock,
          update: (patch: unknown) => {
            updateSpy(patch);
            return { eq: () => ({ eq: () => ({ is: () => ({ in: updateInMock }) }) }) };
          },
        };
      }
      throw new Error(`unexpected table ${table}`);
    },
  }),
}));

const { runGraphReasoner, saveFacts, loadGraphInput } = await import("./graphRun");

const routeFact = {
  path: "/api/invoices",
  file: "app/api/invoices/route.ts",
  methods: ["GET"],
  tables: ["invoices"],
  authenticated: false,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  isApiRoute: true,
  via: [],
};

const vulnerableFacts = [
  { collector: "source", facts: { routes: [routeFact] } },
  { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: false }] } },
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

  it("assembles input from every collector that reported", async () => {
    selectFactsMock.mockResolvedValue({
      data: [
        ...vulnerableFacts,
        { collector: "traffic", facts: { hotPaths: [{ path: "/login", suspiciousRequests: 5 }] } },
      ],
    });
    const input = await loadGraphInput("u1");
    expect(input.routes).toHaveLength(1);
    expect(input.scanTables).toHaveLength(1);
    expect(input.trafficHotPaths).toHaveLength(1);
  });

  // Missing collectors are absent, never faked.
  it("leaves absent collectors undefined", async () => {
    selectFactsMock.mockResolvedValue({ data: [{ collector: "source", facts: { routes: [] } }] });
    const input = await loadGraphInput("u1");
    expect(input.routes).toEqual([]);
    expect(input.scanTables).toBeUndefined();
  });

  it("tolerates a null read", async () => {
    selectFactsMock.mockResolvedValue({ data: null });
    expect(await loadGraphInput("u1")).toEqual({});
  });
});

describe("runGraphReasoner", () => {
  beforeEach(() => {
    selectFactsMock.mockReset().mockResolvedValue({ data: [] });
    findingsSelectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
    updateSpy.mockReset();
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
        { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }] } },
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

  it("writes nothing when there is nothing to change", async () => {
    selectFactsMock.mockResolvedValue({
      data: [
        { collector: "source", facts: { routes: [routeFact] } },
        { collector: "db", facts: { scanTables: [{ name: "invoices", rlsEnabled: true }] } },
      ],
    });
    const result = await runGraphReasoner("u1");
    expect(result.total).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
    expect(updateInMock).not.toHaveBeenCalled();
  });
});
