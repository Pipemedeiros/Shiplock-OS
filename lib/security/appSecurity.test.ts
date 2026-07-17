import { describe, it, expect, vi, beforeEach } from "vitest";

// Attacker-negative security tests for ShipLock's own controls (item 4). These
// prove the controls FAIL CLOSED: authorization gating on the deep routes, and
// token gating on the public traffic endpoints (an unknown/absent/lapsed caller
// must never trigger processing or leak enforcement state). Local mocks only,
// no external systems, no real credentials.

const requireProUserMock = vi.fn();
const singleMock = vi.fn();
const maybeSingleMock = vi.fn();
const runReasoningPassMock = vi.fn();
const ingestTrafficEventMock = vi.fn();
const getActiveBlocklistMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/deep/reasoningRun", () => ({ runReasoningPass: runReasoningPassMock }));
vi.mock("@/lib/traffic/ingest", () => ({ ingestTrafficEvent: ingestTrafficEventMock }));
vi.mock("@/lib/traffic/blocklist", () => ({ getActiveBlocklist: getActiveBlocklistMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({ eq: () => ({ single: singleMock, maybeSingle: maybeSingleMock }) }),
    }),
  }),
}));

const { POST: reasonPOST } = await import("@/app/api/deep/github/reason/route");
const { POST: ingestPOST } = await import("@/app/api/traffic/ingest/route");
const { GET: blocklistGET } = await import("@/app/api/traffic/blocklist/route");

const ingestReq = (headers: Record<string, string>, url = "http://localhost/api/traffic/ingest") =>
  new Request(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ source_id: "x", path: "/login", method: "POST" }) }) as never;

beforeEach(() => {
  [requireProUserMock, singleMock, maybeSingleMock, runReasoningPassMock, ingestTrafficEventMock, getActiveBlocklistMock].forEach((m) => m.mockReset());
});

describe("Authorization bypass — deep reasoning route", () => {
  it("403s a non-Pro caller and never runs the pass", async () => {
    requireProUserMock.mockResolvedValue(null);
    const res = await reasonPOST();
    expect(res.status).toBe(403);
    expect(runReasoningPassMock).not.toHaveBeenCalled();
  });

  it("400s when GitHub is not connected (no installation)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { github_installation_id: null } });
    const res = await reasonPOST();
    expect(res.status).toBe(400);
    expect(runReasoningPassMock).not.toHaveBeenCalled();
  });

  it("does not leak internal errors (generic 502)", async () => {
    requireProUserMock.mockResolvedValue({ userId: "u1", email: "a@b.com" });
    singleMock.mockResolvedValue({ data: { github_installation_id: 42 } });
    runReasoningPassMock.mockRejectedValue(new Error("secret internal token abc123 blew up"));
    const res = await reasonPOST();
    expect(res.status).toBe(502);
    expect(JSON.stringify(await res.json())).not.toContain("abc123");
  });
});

describe("Traffic ingest — token gating fails closed", () => {
  it("no token → generic ok, no processing, no enumeration", async () => {
    const res = await ingestPOST(ingestReq({}));
    expect(await res.json()).toEqual({ ok: true });
    expect(ingestTrafficEventMock).not.toHaveBeenCalled();
  });

  it("unknown token → generic ok, no processing", async () => {
    maybeSingleMock.mockResolvedValue({ data: null });
    const res = await ingestPOST(ingestReq({ "x-site": "bogus" }));
    expect(await res.json()).toEqual({ ok: true });
    expect(ingestTrafficEventMock).not.toHaveBeenCalled();
  });

  it("lapsed (unpaid) subscriber → no processing", async () => {
    maybeSingleMock.mockResolvedValue({ data: { id: "u1", email: "a@b.com", is_paid: false } });
    const res = await ingestPOST(ingestReq({ "x-site": "real-but-lapsed" }));
    expect(await res.json()).toEqual({ ok: true });
    expect(ingestTrafficEventMock).not.toHaveBeenCalled();
  });

  it("paid subscriber → processes the event", async () => {
    maybeSingleMock.mockResolvedValue({ data: { id: "u1", email: "a@b.com", is_paid: true } });
    ingestTrafficEventMock.mockResolvedValue({ action: "none" });
    const res = await ingestPOST(ingestReq({ "x-site": "valid" }));
    expect(await res.json()).toEqual({ ok: true });
    expect(ingestTrafficEventMock).toHaveBeenCalledOnce();
  });
});

describe("Traffic blocklist — never leaks another site's blocks", () => {
  const blReq = (site?: string) =>
    new Request(`http://localhost/api/traffic/blocklist${site ? `?site=${site}` : ""}`) as never;

  it("no/unknown token → empty list, no read", async () => {
    const res1 = await blocklistGET(blReq());
    expect(await res1.json()).toEqual({ hashes: [], ttl: 30 });
    maybeSingleMock.mockResolvedValue({ data: null });
    const res2 = await blocklistGET(blReq("bogus"));
    expect(await res2.json()).toEqual({ hashes: [], ttl: 30 });
    expect(getActiveBlocklistMock).not.toHaveBeenCalled();
  });

  it("lapsed subscriber → empty list (enforcement pauses with the subscription)", async () => {
    maybeSingleMock.mockResolvedValue({ data: { id: "u1", is_paid: false } });
    const res = await blocklistGET(blReq("lapsed"));
    expect(await res.json()).toEqual({ hashes: [], ttl: 30 });
    expect(getActiveBlocklistMock).not.toHaveBeenCalled();
  });
});
