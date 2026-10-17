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
    expect(view.totals).toEqual({ attackers: 2, blocked: 0, attackedRoutes: 2, attackedWithIssue: 1, probablyWorked: 0, unmatchedPaths: 0 });
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

// 104: how the app answered. "Probably worked" needs two layers to agree, or
// a login that succeeded after a run of failures; anything less is said as
// what was seen, and a snippet that cannot see answers says not reported.
describe("attack view: what the app answered", () => {
  const walk = (status: (i: number) => number | null, n = 12) => Array.from({ length: n }, (_, i) =>
    ({ source_id: SRC_A, path: `/api/notes/${2000 + i}`, method: "GET", created_at: at(20 - i / 10), status: status(i) }));
  const alerts = [{ source_id: SRC_A, reason: "Walking record ids: 31 different ids on /api/notes/:id in 5 minutes", alerted_at: at(15), action: "alert" }];
  const outcome = (events: Parameters<typeof buildAttackView>[0]["events"], fs = findings, a = alerts) =>
    buildAttackView({ now: NOW, alerts: a, blocks: [], events, routes, findings: fs }).attackedRoutes[0].outcome;

  it("says probably worked when an open issue's route answered many different record ids", () => {
    const o = outcome(walk(() => 200));
    expect(o.kind).toBe("worked");
    expect(o.detail).toMatch(/12 different record ids/);
  });

  it("says only what was seen when the code shows no issue there", () => {
    expect(outcome(walk(() => 200), []).kind).toBe("answered");
  });

  it("does not count a few answers as a walk that worked", () => {
    expect(outcome(walk((i) => (i < 9 ? 200 : 404))).kind).toBe("answered");
  });

  it("says turned away when every answer refused", () => {
    expect(outcome(walk(() => 403)).kind).toBe("refused");
  });

  it("names server errors on attack requests", () => {
    const o = outcome(walk((i) => (i === 0 ? 500 : 404)));
    expect(o.kind).toBe("errored");
    expect(o.detail).toMatch(/1 of these requests/);
  });

  it("says not reported when the snippet cannot see answers, never refused or clean", () => {
    expect(outcome(walk(() => null)).kind).toBe("unreported");
    const withoutStatus = walk(() => null).map((e) => Object.fromEntries(Object.entries(e).filter(([k]) => k !== "status")) as typeof e);
    expect(outcome(withoutStatus).kind).toBe("unreported");
  });

  it("flags a login that succeeded after a run of failures from the same source", () => {
    const stuffing = [{ source_id: SRC_B, reason: "Credential stuffing: 25 auth attempts in 60s", alerted_at: at(9), action: "block" }];
    const tries = (last: number) => [
      ...Array.from({ length: 6 }, (_, i) => ({ source_id: SRC_B, path: "/api/login", method: "POST", created_at: at(10 - i / 10), status: 401 })),
      { source_id: SRC_B, path: "/api/login", method: "POST", created_at: at(9), status: last },
    ];
    expect(outcome(tries(200), [], stuffing).kind).toBe("worked");
    expect(outcome(tries(200), [], stuffing).detail).toMatch(/signed in after 6 failed/);
    expect(outcome(tries(401), [], stuffing).kind).toBe("refused");
  });

  it("puts routes where it probably worked first, above a confirmed issue that refused, and counts them", () => {
    const rs = [...routes, { path: "/api/files/[id]", file: "app/api/files/[id]/route.ts" }];
    const fs = [...findings, { file: "app/api/files/[id]/route.ts", title: "Files readable by id", severity: "WARNING" as const, confirmed: false }];
    const files = Array.from({ length: 12 }, (_, i) =>
      ({ source_id: SRC_A, path: `/api/files/${3000 + i}`, method: "GET", created_at: at(4), status: 200 }));
    const view = buildAttackView({ now: NOW, alerts, blocks: [], routes: rs, findings: fs, events: [...walk(() => 403), ...files] });
    expect(view.attackedRoutes.map((r) => [r.pattern, r.outcome.kind])).toEqual([
      ["/api/files/[id]", "worked"], ["/api/notes/[id]", "refused"]]);
    expect(view.totals.probablyWorked).toBe(1);
  });
});
