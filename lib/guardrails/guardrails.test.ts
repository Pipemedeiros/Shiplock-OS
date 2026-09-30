import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { checkGuardrails, deriveGuardrails, guardrailsSchema } from "./guardrails";

const route = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/invoices", file: "app/api/invoices/route.ts", methods: ["GET"], tables: ["invoices"],
  authenticated: true, machineGated: false, usesServiceRole: false, ownershipFiltered: true,
  identityReadable: true, ownershipReadable: true, dataReadable: true, machineGateReadable: true, serviceRoleReadable: true,
  identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [], ...over,
} as RouteFact);

describe("deriving guardrails from observed route facts", () => {
  it("turns observed controls into rules and never turns an unread control into one", () => {
    const g = deriveGuardrails([
      route({}),
      route({ path: "/api/cron", file: "app/api/cron/route.ts", authenticated: false, ownershipFiltered: false, machineGated: true }),
      route({ path: "/api/unread", file: "app/api/unread/route.ts", identityReadable: false, ownershipReadable: false }),
      route({ path: "/api/public", file: "app/api/public/route.ts", tables: [], authenticated: false, ownershipFiltered: false }),
    ], { repository: "acme/app", commit: "a".repeat(40) });
    expect(g.rules.map((r) => `${r.kind} ${r.route}`)).toEqual([
      "requires_machine_secret /api/cron",
      "requires_signed_in_caller /api/invoices",
      "scopes_rows_to_caller /api/invoices",
    ]);
    expect(guardrailsSchema.parse(g)).toEqual(g);
    expect(g.rules[1].because).toMatch(/invoices/);
    expect(JSON.stringify(g)).not.toMatch(/[–—]/);
  });
});

describe("checking a change against the guardrails", () => {
  const g = deriveGuardrails([route({})], { repository: "acme/app", commit: "a".repeat(40) });
  const changed = new Set(["app/api/invoices/route.ts"]);

  it("blocks a change that removes an observed control from a route it touched", () => {
    const out = checkGuardrails(g, [route({ authenticated: false, ownershipFiltered: false })], changed);
    expect(out.violations.map((v) => v.kind)).toEqual(["requires_signed_in_caller", "scopes_rows_to_caller"]);
    expect(out.violations[0]).toMatchObject({ severity: "CRITICAL", route: "/api/invoices", file: "app/api/invoices/route.ts" });
  });

  it("passes when the controls hold, and says unread when the new code cannot be read", () => {
    expect(checkGuardrails(g, [route({})], changed)).toEqual({ violations: [], unread: [] });
    const unread = checkGuardrails(g, [route({ identityReadable: false, authenticated: false })], changed);
    expect(unread.violations.map((v) => v.kind)).toEqual([]);
    expect(unread.unread).toEqual(["requires_signed_in_caller /api/invoices"]);
  });

  it("ignores routes the change did not touch, directly or through a helper", () => {
    expect(checkGuardrails(g, [route({ authenticated: false })], new Set(["README.md"])).violations).toEqual([]);
    const viaHelper = checkGuardrails(g, [route({ authenticated: false, via: ["lib/auth.ts"] })], new Set(["lib/auth.ts"]));
    expect(viaHelper.violations).toHaveLength(1);
  });

  it("does not call a deleted route a regression", () => {
    expect(checkGuardrails(g, [], changed)).toEqual({ violations: [], unread: [] });
  });
});
