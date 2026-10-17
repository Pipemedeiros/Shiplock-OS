import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { buildRouteMap } from "@/lib/routeMap";
import { EMPTY_PULSE } from "@/lib/traffic/pulse";
import type { AttackView } from "@/lib/traffic/attackView";
import { TrafficView } from "./TrafficView";

const map = buildRouteMap({
  routes: [{ path: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts", tables: ["notes"], authenticated: false, ownershipFiltered: false, machineGated: false }],
  tools: [], findings: [{ entry: "/api/notes/[id]", severity: "CRITICAL", title: "Anyone can read any note", confirmed: true }], hotFiles: [],
});
const view: AttackView = {
  attackers: [{ alias: "Source a1b2", sourceId: "a1b2c3", kinds: ["Walking record ids"], reasons: ["Walking record ids: 31 different ids on /api/notes/:id in 5 minutes"],
    status: "blocked", blockedUntil: "2026-10-16T13:00:00Z", firstSeen: "2026-10-16T11:25:00Z", lastSeen: "2026-10-16T11:30:00Z", requests: 31,
    routes: [{ pattern: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts", requests: 31 }], unmatchedPaths: 2 }],
  attackedRoutes: [{ pattern: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts", requests: 31, attackers: 1,
    finding: { title: "Anyone can read any note", severity: "CRITICAL", confirmed: true },
    outcome: { kind: "unreported", detail: "Your snippet reports requests, not how your app answered them." } }],
  totals: { attackers: 1, blocked: 1, attackedRoutes: 1, attackedWithIssue: 1, probablyWorked: 0, unmatchedPaths: 2 },
};
const pulse = { ...EMPTY_PULSE, watched: 1200, sources: 40, turnedAway: 18, hasData: true,
  buckets: EMPTY_PULSE.buckets.map((_, i) => i * 3), recentPaths: [{ path: "/api/notes/1031", method: "GET", blocked: true }] };
const base = { repository: "acme/app", sites: 1, installed: true, lastSeenAt: "2026-10-16T11:59:00Z", pulse, view, map, capped: false, gateway: null };
const gateway = [{ path: "/rest/v1/orders", label: "Table orders", suspiciousRequests: 40, answered: 38, observedAt: "2026-10-16T11:00:00Z" },
  { path: "/auth/v1/token", label: "Sign in", suspiciousRequests: 25, answered: null, observedAt: "2026-10-16T11:00:00Z" }];

describe("TrafficView", () => {
  const html = renderToStaticMarkup(<TrafficView {...base} />);

  it("leads with the four numbers: requests, flagged sources, attacked routes, turned away", () => {
    for (const label of ["Requests watched", "Flagged sources", "Attacked routes", "Turned away"]) expect(html).toContain(label);
    expect(html).toContain("1 with an open issue");
  });

  it("puts the sources on the map with what they hit", () => {
    expect(html).toContain('aria-label="traffic source Source a1b2"');
    expect(html).toContain('data-edge="attack"');
  });

  it("lists attacked routes with their issue, and says an attempt is only an attempt", () => {
    expect(html).toContain("Anyone can read any note");
    expect(html).toContain("Confirmed");
    expect(html).toMatch(/Whether one worked shows below, where your snippet reports answers/);
    expect(html).not.toMatch(/compromised|secure|safe\b/i);
  });

  it("lists each flagged source: what it did, where, when, and whether it is blocked", () => {
    expect(html).toContain("Source a1b2");
    expect(html).toContain("Walking record ids");
    expect(html).toContain("Blocked until");
    expect(html).toContain("2 paths that match no route");
  });

  it("gives the volume chart a text summary", () => {
    expect(html).toMatch(/role="img"[^>]*aria-label="Requests per 2 hours over the last 48 hours/);
  });

  it("says traffic is not connected rather than showing an empty, quiet page", () => {
    const off = renderToStaticMarkup(<TrafficView {...base} sites={0} installed={false} lastSeenAt={null} pulse={EMPTY_PULSE} view={null} map={null} />);
    expect(off).toContain("Traffic is not connected");
    expect(off).toContain('href="/dashboard/settings"');
    expect(off).not.toContain("Flagged sources");
  });

  it("says when the attack view could not be read, never that there were no attacks", () => {
    const unread = renderToStaticMarkup(<TrafficView {...base} view={null} />);
    expect(unread).toContain("could not be read");
    expect(unread).not.toMatch(/no attacks|no flagged/i);
  });

  it("says plainly when the snippet has sent nothing for a day", () => {
    const stale = renderToStaticMarkup(<TrafficView {...base} installed={false} />);
    expect(stale).toContain("No request in the last 24 hours");
  });

  // 104: where the snippet reports answers, each attacked route says how the
  // app answered; "probably worked" leads, and it never says compromised.
  it("says how the app answered each attacked route, and leads with probably worked", () => {
    expect(html).toContain("Not reported");
    const worked: AttackView = { ...view, totals: { ...view.totals, probablyWorked: 1 },
      attackedRoutes: [{ ...view.attackedRoutes[0], outcome: { kind: "worked",
        detail: "Your app answered one flagged source with success on 31 different record ids, on a route where the code has an open issue." } }] };
    const w = renderToStaticMarkup(<TrafficView {...base} view={worked} />);
    expect(w).toContain("Probably worked");
    expect(w).toContain("31 different record ids");
    expect(w).toContain("1 probably worked");
    expect(w).not.toMatch(/compromised|breached/i);
  });

  // 105: what the Supabase gateway saw, shown even with no snippet installed,
  // since ShipLock reads it through the Supabase connection.
  it("shows flagged Supabase gateway traffic, with or without a snippet", () => {
    for (const props of [{ ...base, gateway }, { ...base, gateway, sites: 0, installed: false, view: null, map: null }]) {
      const g = renderToStaticMarkup(<TrafficView {...props} />);
      expect(g).toContain("Supabase gateway");
      expect(g).toContain("Table orders");
      expect(g).toContain("38 answered with success");
      expect(g).toContain("Not counted");
      expect(g).not.toMatch(/compromised|stolen|taken/i);
    }
    expect(renderToStaticMarkup(<TrafficView {...base} />)).not.toContain("Supabase gateway");
  });

  it("writes copy with no dashes", () => {
    const text = html.replace(/<[^>]+>/g, " ");
    expect(text).not.toMatch(/[–—]| - /);
  });
});
