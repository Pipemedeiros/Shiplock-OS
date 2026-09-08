import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { MAX_PROMPT_ROUTES, riskyRoutesOmitted, routeRisk } from "./attack";
import type { StackReport } from "./stack";

/**
 * The prompt holds sixty routes. Coverage tells the customer the ones left out
 * "are the ones already scoped or already guarded" — true only while every
 * reportable shape fits under the cap.
 *
 * Measured 2026-09-08: corpus-a sits at 54 routes in risk bands 0–5 against a cap of
 * 60. Seven more anonymous or unscoped routes and real candidates start being
 * dropped, silently, under a Coverage note that still calls them safe. The
 * output would be indistinguishable from a clean scan.
 *
 * Raising the cap was rejected: candidate composition governs precision more
 * than any fact fix in this project's measurements. So the cap stays and the
 * silence is what gets fixed.
 */

const route = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/x",
  file: "app/api/x/route.ts",
  methods: ["GET"],
  tables: ["thing"],
  authenticated: false,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  ownershipReadable: true,
  ownershipGap: null,
  serviceRoleReadable: true,
  machineGateReadable: true,
  machineGateGap: null,
  via: [],
  ...over,
});

const stack: StackReport = { tools: [], authUnknown: true, databaseUnknown: true } as unknown as StackReport;
const input = (routes: RouteFact[]) => ({ routes, stack, tables: ["thing"], domain: undefined, files: [] as string[], liveFacts: [] });

/** Band 6: authenticated AND scoped — nothing to report, safe to drop. */
const safe = (i: number) => route({ path: `/api/safe/${i}`, authenticated: true, ownershipFiltered: true });
/** Band 1: anonymous and unscoped — the open door. */
const risky = (i: number) => route({ path: `/api/risky/${i}` });

describe("the truncation fuse", () => {
  it("is silent while every reportable route fits under the cap", () => {
    // 5 risky + 100 safe. Ranking puts the risky ones first, so the cut is all
    // band 6. This is every corpus repository today.
    const routes = [...Array.from({ length: 5 }, (_, i) => risky(i)), ...Array.from({ length: 100 }, (_, i) => safe(i))];
    expect(routes.length).toBeGreaterThan(MAX_PROMPT_ROUTES);
    expect(riskyRoutesOmitted(input(routes))).toBe(0);
  });

  it("fires when a reportable route is pushed past the cap", () => {
    // 65 risky routes against a cap of 60: five get dropped, and they are
    // exactly the ones the product exists to report.
    const routes = Array.from({ length: MAX_PROMPT_ROUTES + 5 }, (_, i) => risky(i));
    expect(riskyRoutesOmitted(input(routes))).toBe(5);
  });

  it("counts only reportable shapes, not every dropped route", () => {
    const routes = [
      ...Array.from({ length: MAX_PROMPT_ROUTES + 2 }, (_, i) => risky(i)),
      ...Array.from({ length: 40 }, (_, i) => safe(i)),
    ];
    // 102 routes, 42 dropped — but only the 2 risky ones matter.
    expect(riskyRoutesOmitted(input(routes))).toBe(2);
  });

  it("never fires when nothing is truncated at all", () => {
    expect(riskyRoutesOmitted(input([risky(1), risky(2)]))).toBe(0);
  });

  it("ignores routes that reach no data, since those never enter the prompt", () => {
    const routes = [
      ...Array.from({ length: MAX_PROMPT_ROUTES }, (_, i) => safe(i)),
      ...Array.from({ length: 10 }, (_, i) => route({ path: `/api/notable/${i}`, tables: [] })),
    ];
    expect(riskyRoutesOmitted(input(routes))).toBe(0);
  });

  it("rests on the band boundary it claims to: 0-5 reportable, 6 not", () => {
    // If routeRisk ever stops putting authenticated+scoped alone in band 6,
    // the fuse silently stops meaning what it says. Pin the boundary here.
    const sensitive = new Set<string>();
    expect(routeRisk(safe(0), sensitive)).toBe(6);
    expect(routeRisk(risky(0), sensitive)).toBeLessThan(6);
    expect(routeRisk(route({ authenticated: true }), sensitive)).toBeLessThan(6); // authed + unscoped
    expect(routeRisk(route({ ownershipFiltered: true }), sensitive)).toBeLessThan(6); // anonymous + scoped
  });
});
