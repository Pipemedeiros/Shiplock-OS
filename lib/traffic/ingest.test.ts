import { beforeEach, describe, expect, it, vi } from "vitest";

// The one write in the traffic layer: the event row. A status is stored only
// when the snippet reported one, so events from snippets that cannot see the
// response still insert as before.
const s = vi.hoisted(() => ({ inserts: [] as Record<string, unknown>[] }));
vi.mock("./alerts", () => ({ sendThreatAlert: vi.fn() }));
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

beforeEach(() => { s.inserts.length = 0; });

describe("ingestTrafficEvent stores the response status", () => {
  it("keeps a reported status and omits the column when none was reported", async () => {
    await ingestTrafficEvent({ userId: "u", email: null, event: { ...event, status: 200 } });
    await ingestTrafficEvent({ userId: "u", email: null, event });
    expect(s.inserts[0].status).toBe(200);
    expect("status" in s.inserts[1]).toBe(false);
  });
});
