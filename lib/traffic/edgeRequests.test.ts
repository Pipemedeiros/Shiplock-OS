import { describe, expect, it } from "vitest";
import { analyzeEdgeRequests as analyzeAny, hashSource } from "./edgeRequests";

/** Narrow to a readable analysis; the unread shape has its own test. */
const analyzeEdgeRequests = (rows: unknown[], salt: string) => {
  const out = analyzeAny(rows, salt);
  if (!out.readable) return out as never as { readable: false; rowsRead: number; judged: never[]; hotPaths: never[] };
  return out;
};

// 2F-4: Supabase's API gateway log, read with the customer's own connection,
// judged by the same rules as the snippet. IPs are hashed immediately.
const t0 = Date.parse("2026-09-23T10:00:00Z");
const row = (ip: string, path: string, offsetMs: number, status = 401) =>
  ({ ts: new Date(t0 + offsetMs).toISOString(), method: "POST", path, status, ip });

describe("analyzeEdgeRequests (2F-4)", () => {
  it("flags credential stuffing from one source and reports the paths it hit", () => {
    const rows = Array.from({ length: 25 }, (_, i) => row("203.0.113.9", "/auth/v1/token?grant_type=password", i * 1000));
    rows.push(row("198.51.100.2", "/rest/v1/orders", 5000, 200));
    const out = analyzeEdgeRequests(rows, "salt");
    expect(out.readable).toBe(true);
    expect(out.judged).toHaveLength(1);
    expect(out.judged[0]).toMatchObject({ action: "block" });
    expect(out.judged[0].reason).toMatch(/Credential stuffing/);
    expect(out.hotPaths).toEqual([{ path: "/auth/v1/token", suspiciousRequests: 25 }]);
  });

  it("never exposes a raw IP: sources are keyed, salted hashes", () => {
    const rows = Array.from({ length: 25 }, (_, i) => row("203.0.113.9", "/auth/v1/token", i * 1000));
    const out = analyzeEdgeRequests(rows, "salt");
    expect(JSON.stringify(out)).not.toContain("203.0.113.9");
    expect(out.judged[0].sourceId).toBe(hashSource("203.0.113.9", "salt"));
    expect(hashSource("203.0.113.9", "salt")).not.toBe(hashSource("203.0.113.9", "other-day"));
  });

  it("judges on the busiest window, not the whole day", () => {
    // 25 auth attempts spread over 25 minutes never reach 20 in any minute.
    const slow = Array.from({ length: 25 }, (_, i) => row("192.0.2.1", "/auth/v1/token", i * 60_000));
    expect(analyzeEdgeRequests(slow, "salt").judged).toEqual([]);
  });

  it("treats an unreadable or empty response as unread, never as quiet", () => {
    expect(analyzeEdgeRequests([{ nope: true } as never], "salt")).toMatchObject({ readable: false });
    expect(analyzeEdgeRequests([], "salt")).toMatchObject({ readable: true, judged: [], hotPaths: [] });
  });
});
