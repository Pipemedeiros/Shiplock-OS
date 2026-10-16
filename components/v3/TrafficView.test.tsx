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
    finding: { title: "Anyone can read any note", severity: "CRITICAL", confirmed: true } }],
  totals: { attackers: 1, blocked: 1, attackedRoutes: 1, attackedWithIssue: 1, unmatchedPaths: 2 },
};
const pulse = { ...EMPTY_PULSE, watched: 1200, sources: 40, turnedAway: 18, hasData: true,
  buckets: EMPTY_PULSE.buckets.map((_, i) => i * 3), recentPaths: [{ path: "/api/notes/1031", method: "GET", blocked: true }] };
const base = { repository: "acme/app", sites: 1, installed: true, lastSeenAt: "2026-10-16T11:59:00Z", pulse, view, map, capped: false };

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

  it("lists attacked routes with their issue, and says traffic shows attempts, not outcomes", () => {
    expect(html).toContain("Anyone can read any note");
    expect(html).toContain("Confirmed");
    expect(html).toMatch(/attempts, not whether they worked/);
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

  it("writes copy with no dashes", () => {
    const text = html.replace(/<[^>]+>/g, " ");
    expect(text).not.toMatch(/[–—]| - /);
  });
});
