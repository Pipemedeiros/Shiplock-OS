import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const insertMock = vi.fn();
const selectMock = vi.fn();
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

const { runProvingGround, persistProvenFindings } = await import("./run");

const schema = new Map([["invoices", ["id", "user_id"]]]);
const on = { killSwitchOn: false, provingGroundEnabled: true };

describe("runProvingGround — refusals happen before any spending", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });
  afterEach(() => vi.unstubAllGlobals());

  it("refuses on the kill switch without creating a branch", async () => {
    const r = await runProvingGround("u1", "t", "prod", { ...on, killSwitchOn: true }, ["public.invoices"], schema);
    expect(r).toMatchObject({ ran: false, reason: "kill_switch" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses without opt-in without creating a branch", async () => {
    const r = await runProvingGround("u1", "t", "prod", { ...on, provingGroundEnabled: false }, ["public.invoices"], schema);
    expect(r.reason).toBe("not_enabled");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  // Standing up a branch to test nothing is pure cost.
  it("does not create a branch when there is nothing to probe", async () => {
    const r = await runProvingGround("u1", "t", "prod", on, [], schema);
    expect(r.reason).toBe("nothing_to_probe");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("reports branch_unavailable when creation fails", async () => {
    fetchMock.mockResolvedValue({ ok: false, json: async () => ({}) });
    const r = await runProvingGround("u1", "t", "prod", on, ["public.invoices"], schema);
    expect(r).toMatchObject({ ran: false, reason: "branch_unavailable" });
  });
});

describe("runProvingGround — teardown is unconditional", () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });
  afterEach(() => vi.unstubAllGlobals());

  const deleteCalls = () =>
    fetchMock.mock.calls.filter((c) => (c[1] as { method?: string })?.method === "DELETE");

  it("deletes the branch after a successful run", async () => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === "POST" && String(url).endsWith("/branches")) {
        return { ok: true, json: async () => ({ ref: "branch-1" }) };
      }
      if (init?.method === "DELETE") return { ok: true, json: async () => ({}) };
      return { ok: true, json: async () => [{ leaked: 1 }] };
    });

    const r = await runProvingGround("u1", "t", "prod", on, ["public.invoices"], schema);
    expect(r.ran).toBe(true);
    expect(r.findings).toHaveLength(1);
    expect(deleteCalls()).toHaveLength(1);
  });

  // A leaked branch bills the customer indefinitely for something they cannot see.
  it("deletes the branch even when every probe throws", async () => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === "POST" && String(url).endsWith("/branches")) {
        return { ok: true, json: async () => ({ ref: "branch-1" }) };
      }
      if (init?.method === "DELETE") return { ok: true, json: async () => ({}) };
      throw new Error("query exploded");
    });

    const r = await runProvingGround("u1", "t", "prod", on, ["public.invoices"], schema);
    expect(r.findings).toEqual([]);
    expect(deleteCalls()).toHaveLength(1);
  });

  it("reports nothing when isolation held", async () => {
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === "POST" && String(url).endsWith("/branches")) {
        return { ok: true, json: async () => ({ ref: "branch-1" }) };
      }
      if (init?.method === "DELETE") return { ok: true, json: async () => ({}) };
      return { ok: true, json: async () => [{ leaked: 0 }] };
    });

    const r = await runProvingGround("u1", "t", "prod", on, ["public.invoices"], schema);
    expect(r.ran).toBe(true);
    expect(r.findings).toEqual([]);
  });
});

describe("persistProvenFindings", () => {
  beforeEach(() => {
    selectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });

  const finding = {
    id: "proven:tenant_isolation:public.invoices",
    severity: "CRITICAL" as const,
    title: "t",
    consequence: "c",
    proven: true as const,
  };

  it("inserts a newly proven finding", async () => {
    const r = await persistProvenFindings("u1", [finding], 1);
    expect(r.newCount).toBe(1);
    expect(insertMock.mock.calls[0][0][0].source).toBe("proven");
  });

  it("closes a proven finding once the probe stops reproducing it", async () => {
    selectMock.mockResolvedValue({ data: [{ finding_id: finding.id }] });
    const r = await persistProvenFindings("u1", [], 1);
    expect(r.resolvedCount).toBe(1);
  });

  // Replacing evidence with an absence of evidence is the one thing a PROVEN
  // finding must never suffer.
  it("does NOT close a proven finding when nothing was probed", async () => {
    selectMock.mockResolvedValue({ data: [{ finding_id: finding.id }] });
    const r = await persistProvenFindings("u1", [], 0);
    expect(r.resolvedCount).toBe(0);
    expect(updateInMock).not.toHaveBeenCalled();
  });
});
