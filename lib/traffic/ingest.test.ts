import { beforeEach, describe, expect, it, vi } from "vitest";

// The one write in the traffic layer: the event row. A status is stored only
// when the snippet reported one, so events from snippets that cannot see the
// response still insert as before.
const s = vi.hoisted(() => ({ inserts: [] as Record<string, unknown>[], alert: vi.fn() }));
vi.mock("./alerts", () => ({ sendThreatAlert: s.alert }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => {
      const q: Record<string, unknown> = {};
      Object.assign(q, {
        insert: async (row: Record<string, unknown>) => { s.inserts.push(row); return { error: null }; },
        select: () => q, eq: () => q, gte: () => q, order: () => q,
        limit: async () => ({ data: [], error: null }),
      });
      return q;
    },
  }),
}));
const { ingestTrafficEvent } = await import("./ingest");
const event = { source_id: "s", path: "/api/orders/1", method: "GET", ua: null, t: 0 };

beforeEach(() => { s.inserts.length = 0; s.alert.mockReset(); });

describe("ingestTrafficEvent stores the response status", () => {
  it("keeps a reported status and omits the column when none was reported", async () => {
    await ingestTrafficEvent({ userId: "u", email: null, event: { ...event, status: 200 } });
    await ingestTrafficEvent({ userId: "u", email: null, event });
    expect(s.inserts[0].status).toBe(200);
    expect("status" in s.inserts[1]).toBe(false);
  });
});

describe("ingestTrafficEvent flags a scanner that names itself (CRS 913100)", () => {
  it("alerts once on a sqlmap request and stays quiet for a browser", async () => {
    expect(await ingestTrafficEvent({ userId: "u", email: null, event: { ...event, ua: "sqlmap/1.7.2#stable (https://sqlmap.org)" } }))
      .toEqual({ action: "alert" });
    expect(s.alert.mock.calls[0][3]).toMatchObject({ reason: "Scanner tool: sqlmap on /api/orders/1" });
    expect(await ingestTrafficEvent({ userId: "u", email: null, event: { ...event, ua: "Mozilla/5.0 Chrome/141.0" } }))
      .toEqual({ action: "none" });
    expect(s.alert).toHaveBeenCalledTimes(1);
  });
});
