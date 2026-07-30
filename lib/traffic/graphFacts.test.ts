import { describe, it, expect, vi, beforeEach } from "vitest";

const alertMock = vi.fn();
const blockMock = vi.fn();
const eventsMock = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "traffic_alert_log") {
        return { select: () => ({ eq: () => ({ gte: () => ({ limit: alertMock }) }) }) };
      }
      if (table === "traffic_blocklist") {
        return { select: () => ({ eq: () => ({ limit: blockMock }) }) };
      }
      if (table === "traffic_events") {
        return { select: () => ({ eq: () => ({ gte: () => ({ in: () => ({ limit: eventsMock }) }) }) }) };
      }
      throw new Error(`unexpected table ${table}`);
    },
  }),
}));

const { collectTrafficFacts } = await import("./graphFacts");

describe("collectTrafficFacts", () => {
  beforeEach(() => {
    alertMock.mockReset().mockResolvedValue({ data: [] });
    blockMock.mockReset().mockResolvedValue({ data: [] });
    eventsMock.mockReset().mockResolvedValue({ data: [] });
  });

  // Urgency built on a guess would make us cry wolf about real vulnerabilities.
  it("returns nothing when no source has been flagged", async () => {
    expect(await collectTrafficFacts("u1")).toEqual([]);
    expect(eventsMock).not.toHaveBeenCalled();
  });

  it("counts requests per path from flagged sources", async () => {
    alertMock.mockResolvedValue({ data: [{ source_id: "s1" }] });
    eventsMock.mockResolvedValue({
      data: [{ path: "/login" }, { path: "/login" }, { path: "/signup" }],
    });
    expect(await collectTrafficFacts("u1")).toEqual([
      { path: "/login", suspiciousRequests: 2 },
      { path: "/signup", suspiciousRequests: 1 },
    ]);
  });

  it("counts blocklisted sources as well as alerted ones", async () => {
    blockMock.mockResolvedValue({ data: [{ source_id: "s2" }] });
    eventsMock.mockResolvedValue({ data: [{ path: "/login" }] });
    expect(await collectTrafficFacts("u1")).toHaveLength(1);
  });

  it("dedupes a source that is both alerted and blocked", async () => {
    alertMock.mockResolvedValue({ data: [{ source_id: "s1" }] });
    blockMock.mockResolvedValue({ data: [{ source_id: "s1" }] });
    eventsMock.mockResolvedValue({ data: [{ path: "/login" }] });
    await collectTrafficFacts("u1");
    expect(eventsMock).toHaveBeenCalled();
  });

  it("orders by volume, then deterministically by path", async () => {
    alertMock.mockResolvedValue({ data: [{ source_id: "s1" }] });
    eventsMock.mockResolvedValue({ data: [{ path: "/b" }, { path: "/a" }] });
    expect((await collectTrafficFacts("u1")).map((h) => h.path)).toEqual(["/a", "/b"]);
  });

  it("ignores malformed rows rather than throwing", async () => {
    alertMock.mockResolvedValue({ data: [{ source_id: "s1" }, { source_id: null }] });
    eventsMock.mockResolvedValue({ data: [{ path: "/login" }, { path: null }, {}] });
    expect(await collectTrafficFacts("u1")).toEqual([{ path: "/login", suspiciousRequests: 1 }]);
  });

  it("tolerates null reads", async () => {
    alertMock.mockResolvedValue({ data: null });
    blockMock.mockResolvedValue({ data: null });
    expect(await collectTrafficFacts("u1")).toEqual([]);
  });
});
