import { beforeEach, describe, expect, it, vi } from "vitest";

// An external uptime monitor polls this. It says whether the app and the
// database answer, with no data, no version and no error text.
const probe = vi.fn();
const broken = { on: false };
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => { if (broken.on) throw new TypeError("client unavailable"); return { from: () => ({ select: () => ({ limit: probe }) }) }; },
}));
const { GET } = await import("./route");

describe("GET /api/health", () => {
  beforeEach(() => { probe.mockReset(); broken.on = false; });

  it("is 200 when the database answers, and never cached", async () => {
    probe.mockResolvedValue({ error: null });
    const res = await GET();
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, database: "up" });
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("is 503 without leaking the error when the database fails or hangs", async () => {
    probe.mockResolvedValue({ error: { message: "password authentication failed for user x" } });
    const res = await GET();
    expect(res.status).toBe(503);
    expect(JSON.stringify(await res.json())).toBe('{"ok":false,"database":"down"}');
  });

  it("is 503 when the database client throws", async () => {
    broken.on = true;
    expect((await GET()).status).toBe(503);
  });
});
