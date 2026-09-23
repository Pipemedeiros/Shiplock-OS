import { describe, it, expect, vi, beforeEach } from "vitest";

// Attacker-negative security tests for ShipLock's own controls (item 4). These
// prove the controls FAIL CLOSED: authorization gating on the deep routes, and
// token gating on the public traffic endpoints (an unknown/absent/lapsed caller
// must never trigger processing or leak enforcement state). Local mocks only,
// no external systems, no real credentials.

const requireProUserMock = vi.fn();
const singleMock = vi.fn();
const maybeSingleMock = vi.fn();
const ingestTrafficEventMock = vi.fn();
const getActiveBlocklistMock = vi.fn();

vi.mock("@/lib/deep/proGate", () => ({ requireProUser: requireProUserMock }));
vi.mock("@/lib/traffic/ingest", () => ({ ingestTrafficEvent: ingestTrafficEventMock }));
vi.mock("@/lib/traffic/blocklist", () => ({ getActiveBlocklist: getActiveBlocklistMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      // Legacy account tokens only: no traffic site matches in these tests.
      const q = { select: () => q, eq: () => q, is: () => q, single: singleMock,
        maybeSingle: table === "traffic_sites" ? async () => ({ data: null }) : maybeSingleMock };
      return q;
    },
  }),
}));

const { POST: ingestPOST } = await import("@/app/api/traffic/ingest/route");
const { GET: blocklistGET } = await import("@/app/api/traffic/blocklist/route");

const ingestReq = (headers: Record<string, string>, url = "http://localhost/api/traffic/ingest") =>
  new Request(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify({ source_id: "x", path: "/login", method: "POST" }) }) as never;

beforeEach(() => {
  [requireProUserMock, singleMock, maybeSingleMock, ingestTrafficEventMock, getActiveBlocklistMock].forEach((m) => m.mockReset());
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
    const res = await ingestPOST(ingestReq({ "x-site": "33333333-3333-4333-8333-333333333333" }));
    expect(await res.json()).toEqual({ ok: true });
    expect(ingestTrafficEventMock).not.toHaveBeenCalled();
  });

  it("paid subscriber → processes the event", async () => {
    maybeSingleMock.mockResolvedValue({ data: { id: "u1", email: "a@b.com", is_paid: true } });
    ingestTrafficEventMock.mockResolvedValue({ action: "none" });
    const res = await ingestPOST(ingestReq({ "x-site": "44444444-4444-4444-8444-444444444444" }));
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
    const res = await blocklistGET(blReq("55555555-5555-4555-8555-555555555555"));
    expect(await res.json()).toEqual({ hashes: [], ttl: 30 });
    expect(getActiveBlocklistMock).not.toHaveBeenCalled();
  });
});
