import { describe, it, expect, vi, beforeEach } from "vitest";

const selectMock = vi.fn();
const insertMock = vi.fn();
const updateInMock = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({ eq: () => ({ eq: () => ({ is: selectMock }) }) }),
      insert: insertMock,
      update: () => ({ eq: () => ({ eq: () => ({ is: () => ({ in: updateInMock }) }) }) }),
    }),
  }),
}));

const openArenaMock = vi.fn();
vi.mock("./arena", () => ({ openArena: openArenaMock }));

const { runProvingGround, persistProvenFindings } = await import("./run");

const settings = { killSwitchOn: false, provingGroundEnabled: true };
const schema = new Map([["invoices", ["id", "user_id", "amount"]]]);
const policiesByTable = new Map([["invoices", []]]);

/** An arena whose responses are scripted by SQL shape. */
function fakeArena(over: { control?: number; leaked?: number; kind?: "branch" | "replica" } = {}) {
  const teardown = vi.fn().mockResolvedValue(undefined);
  const run = vi.fn(async (sql: string) => {
    if (/as visible/.test(sql)) return [{ visible: over.control ?? 1 }];
    if (/as leaked,/.test(sql)) return [{ leaked: over.leaked ?? 0, own: 1 }];
    if (/as leaked/.test(sql)) return [{ leaked: over.leaked ?? 0 }];
    return [];
  });
  return {
    arena: { kind: over.kind ?? "replica", schema: "proving_x", description: "d", run, teardown },
    teardown,
    run,
  };
}

const ctx = (over: Record<string, unknown> = {}) => ({
  userId: "u1",
  customerToken: "t",
  customerRef: "prod",
  settings,
  suspectedTables: ["public.invoices"],
  schema,
  policiesByTable,
  host: null,
  propose: vi.fn().mockResolvedValue([]),
  ...over,
});

describe("refusals happen before any arena is opened", () => {
  beforeEach(() => {
    openArenaMock.mockReset();
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });

  it("refuses on the kill switch", async () => {
    const r = await runProvingGround(ctx({ settings: { ...settings, killSwitchOn: true } }));
    expect(r).toMatchObject({ ran: false, reason: "kill_switch" });
    expect(openArenaMock).not.toHaveBeenCalled();
  });

  it("refuses without opt-in", async () => {
    const r = await runProvingGround(ctx({ settings: { ...settings, provingGroundEnabled: false } }));
    expect(r.reason).toBe("not_enabled");
    expect(openArenaMock).not.toHaveBeenCalled();
  });

  it("opens nothing when there is nothing to probe", async () => {
    const r = await runProvingGround(ctx({ suspectedTables: [] }));
    expect(r.reason).toBe("nothing_to_probe");
    expect(openArenaMock).not.toHaveBeenCalled();
  });
});

describe("proving a table", () => {
  beforeEach(() => {
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
    openArenaMock.mockReset();
  });

  it("reports a leak found by the deterministic probe", async () => {
    const { arena } = fakeArena({ leaked: 1 });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    const r = await runProvingGround(ctx());
    expect(r.findings).toHaveLength(1);
    expect(r.probed).toBe(1);
  });

  it("reports nothing when isolation holds and the agent finds nothing", async () => {
    const { arena } = fakeArena({ leaked: 0 });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    const r = await runProvingGround(ctx());
    expect(r.findings).toEqual([]);
  });

  // A broken arena reports "no leak" for everything, so a silent setup failure
  // would become a clean bill of health.
  it("does not trust a run whose control probe fails", async () => {
    const { arena } = fakeArena({ control: 0, leaked: 1 });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    const r = await runProvingGround(ctx());
    expect(r.findings).toEqual([]);
  });

  // Only worth a model call once the free check has come up empty.
  it("runs the agent ONLY when the deterministic probe found nothing", async () => {
    const propose = vi.fn().mockResolvedValue([]);
    const { arena } = fakeArena({ leaked: 1 });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    await runProvingGround(ctx({ propose }));
    expect(propose).not.toHaveBeenCalled();

    propose.mockClear();
    const clean = fakeArena({ leaked: 0 });
    openArenaMock.mockResolvedValue({ arena: clean.arena, reason: "" });
    await runProvingGround(ctx({ propose }));
    expect(propose).toHaveBeenCalled();
  });

  it("tears the arena down on success", async () => {
    const { arena, teardown } = fakeArena({ leaked: 1 });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    await runProvingGround(ctx());
    expect(teardown).toHaveBeenCalledOnce();
  });

  it("tears the arena down when probing throws", async () => {
    const { arena, teardown } = fakeArena();
    arena.run = vi.fn().mockRejectedValue(new Error("boom"));
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    await runProvingGround(ctx());
    expect(teardown).toHaveBeenCalledOnce();
  });

  // No arena is a normal outcome, not an error: the static reasoner already
  // reported the table, we just could not upgrade inference to proof.
  it("skips a table with no arena without failing the run", async () => {
    openArenaMock.mockResolvedValue({ arena: null, reason: "policy too complex to rebuild" });
    const r = await runProvingGround(ctx());
    expect(r).toMatchObject({ ran: false, probed: 0, findings: [] });
  });

  it("seeds only on a branch arena — replicas are seeded at setup", async () => {
    const replica = fakeArena({ leaked: 1 });
    openArenaMock.mockResolvedValue({ arena: replica.arena, reason: "" });
    await runProvingGround(ctx());
    expect(replica.run.mock.calls.some(([sql]) => /insert into/i.test(sql))).toBe(false);

    const branch = fakeArena({ leaked: 1, kind: "branch" });
    openArenaMock.mockResolvedValue({ arena: branch.arena, reason: "" });
    await runProvingGround(ctx());
    expect(branch.run.mock.calls.some(([sql]) => /insert into/i.test(sql))).toBe(true);
  });

  it("attaches validated fix evidence to the finding", async () => {
    const { arena } = fakeArena({ leaked: 1 });
    // After the fix is applied the gate query must show it closed and preserved.
    let applied = false;
    arena.run = vi.fn(async (sql: string) => {
      if (/create policy/i.test(sql)) { applied = true; return []; }
      if (/as visible/.test(sql)) return [{ visible: 1 }];
      if (/as leaked,/.test(sql)) return [{ leaked: applied ? 0 : 1, own: 1 }];
      if (/as leaked/.test(sql)) return [{ leaked: 1 }];
      return [];
    });
    openArenaMock.mockResolvedValue({ arena, reason: "" });
    const r = await runProvingGround(ctx());
    expect(r.findings[0].consequence).toContain("Tested on a copy");
  });
});

describe("persistProvenFindings", () => {
  beforeEach(() => {
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });

  const finding = { id: "proven:x", severity: "CRITICAL" as const, title: "t", consequence: "c", proven: true as const };

  it("inserts a new finding", async () => {
    expect((await persistProvenFindings("u1", [finding], 1)).newCount).toBe(1);
  });

  it("closes one that no longer reproduces", async () => {
    selectMock.mockResolvedValue({ data: [{ finding_id: "proven:x" }] });
    expect((await persistProvenFindings("u1", [], 1)).resolvedCount).toBe(1);
  });

  // Replacing evidence with an absence of evidence is the one thing a PROVEN
  // finding must never suffer.
  it("does NOT close anything when nothing was probed", async () => {
    selectMock.mockResolvedValue({ data: [{ finding_id: "proven:x" }] });
    expect((await persistProvenFindings("u1", [], 0)).resolvedCount).toBe(0);
    expect(updateInMock).not.toHaveBeenCalled();
  });
});
