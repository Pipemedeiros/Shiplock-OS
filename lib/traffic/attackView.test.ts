import { describe, expect, it } from "vitest";
import { attackKind, buildAttackView, sourceAlias } from "./attackView";

const NOW = Date.parse("2026-10-16T12:00:00Z");
const at = (minAgo: number) => new Date(NOW - minAgo * 60_000).toISOString();
const SRC_A = "a1b2c3d4e5f6";
const SRC_B = "ffee00112233";

// The audit's own routes (stored route facts): matched by file, named by the audit's path.
const routes = [
  { path: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts" },
  { path: "/api/login", file: "app/api/login/route.ts" },
  { path: "/api/health", file: "app/api/health/route.ts" },
];
const findings = [
  { file: "app/api/notes/[id]/route.ts", title: "Anyone can read any note", severity: "CRITICAL" as const, confirmed: true },
];

describe("attack view: who attacked which route, from metadata ShipLock already holds", () => {
  it("names each attack by its kind in plain words", () => {
    expect(attackKind("Walking record ids: 31 different ids on /api/notes/:id in 5 minutes")).toBe("Walking record ids");
    expect(attackKind("Attack probe: SQL injection pattern on /api/search")).toBe("Attack probe");
    expect(attackKind("")).toBe("Flagged");
  });

  it("gives a source a short alias, never its full hash", () => {
    expect(sourceAlias(SRC_A)).toBe("Source a1b2");
    expect(sourceAlias(SRC_A)).not.toContain("c3d4");
  });

  it("groups flagged sources with what they did, where, and whether they are blocked", () => {
    const view = buildAttackView({
      now: NOW,
      alerts: [
        { source_id: SRC_A, reason: "Walking record ids: 31 different ids on /api/notes/:id in 5 minutes", alerted_at: at(30), action: "alert" },
        { source_id: SRC_B, reason: "Credential stuffing: 25 auth attempts in 60s", alerted_at: at(10), action: "block" },
      ],
      blocks: [{ source_id: SRC_B, reason: "Credential stuffing: 25 auth attempts in 60s", blocked_at: at(10), expires_at: at(-50) }],
      events: [
        ...Array.from({ length: 31 }, (_, i) => ({ source_id: SRC_A, path: `/api/notes/${1000 + i}`, created_at: at(35 - i / 10) })),
        ...Array.from({ length: 25 }, () => ({ source_id: SRC_B, path: "/api/login", created_at: at(11) })),
        { source_id: "unflagged", path: "/api/notes/1", created_at: at(5) },
      ],
      routes, findings,
    });
    expect(view.attackers.map((a) => a.alias)).toEqual(["Source ffee", "Source a1b2"]);
    const walker = view.attackers.find((a) => a.alias === "Source a1b2")!;
    expect(walker).toMatchObject({ status: "flagged", kinds: ["Walking record ids"], requests: 31 });
    expect(walker.routes).toEqual([{ pattern: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts", requests: 31 }]);
    expect(view.attackers[0]).toMatchObject({ status: "blocked", blockedUntil: at(-50) });
    // Unflagged visitors are counted nowhere here.
    expect(view.attackers.some((a) => a.alias.includes("unfl"))).toBe(false);
  });

  it("ranks attacked routes with an open confirmed issue first, joined by file", () => {
    const view = buildAttackView({
      now: NOW,
      alerts: [
        { source_id: SRC_A, reason: "Attack probe: SQL injection pattern on /api/notes/7", alerted_at: at(3), action: "alert" },
        { source_id: SRC_B, reason: "Request flood: 140 requests in 60s", alerted_at: at(2), action: "block" },
      ],
      blocks: [],
      events: [
        { source_id: SRC_A, path: "/api/notes/7", created_at: at(3) },
        ...Array.from({ length: 140 }, () => ({ source_id: SRC_B, path: "/api/health", created_at: at(2) })),
      ],
      routes, findings,
    });
    expect(view.attackedRoutes.map((r) => r.pattern)).toEqual(["/api/notes/[id]", "/api/health"]);
    expect(view.attackedRoutes[0]).toMatchObject({ requests: 1, attackers: 1, finding: { title: "Anyone can read any note", confirmed: true } });
    expect(view.attackedRoutes[1].finding).toBeNull();
    expect(view.totals).toEqual({ attackers: 2, blocked: 0, attackedRoutes: 2, attackedWithIssue: 1, unmatchedPaths: 0 });
  });

  it("keeps paths it cannot place as unmatched, never on a guessed route", () => {
    const view = buildAttackView({
      now: NOW,
      alerts: [{ source_id: SRC_A, reason: "Vulnerability scanning: probed 6 sensitive paths", alerted_at: at(1), action: "block" }],
      blocks: [], routes, findings,
      events: [{ source_id: SRC_A, path: "/.env", created_at: at(1) }, { source_id: SRC_A, path: "/wp-admin", created_at: at(1) }],
    });
    expect(view.attackedRoutes).toEqual([]);
    expect(view.attackers[0].unmatchedPaths).toBe(2);
    expect(view.totals.unmatchedPaths).toBe(2);
  });

  it("ignores anything older than the 48 hour window events are kept for", () => {
    const view = buildAttackView({
      now: NOW,
      alerts: [{ source_id: SRC_A, reason: "Request flood: 120 requests in 60s", alerted_at: at(60 * 49), action: "block" }],
      blocks: [], events: [], routes, findings,
    });
    expect(view.attackers).toEqual([]);
  });
});
