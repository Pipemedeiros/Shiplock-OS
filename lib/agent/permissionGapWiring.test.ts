import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { collectRoutes } from "@/lib/graph/routeInventory";
import { rankRoutes, riskyRoutesOmitted, MAX_PROMPT_ROUTES } from "./attack";
import { buildFindings } from "./findings";

// Step 7C-2: a read permission gap ranks a route into the reportable bands (so
// the reasoning budget and the truncation fuse count it) and becomes a
// WARNING, manual, source-read finding. Synthetic fixtures only.
const gap = { file: "app/api/import/route.ts", method: "POST", model: "project", requires: ["tasks.write"],
  expected: "projects.write", witness: { file: "app/api/projects/route.ts", method: "POST" }, tier: "declared" as const };
const r = (over: Partial<RouteFact>): RouteFact => ({ path: "/api/x", file: "app/api/x/route.ts", methods: ["POST"],
  authenticated: true, machineGated: false, ownershipFiltered: true, identityReadable: true, identityGap: null,
  ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null,
  dataReadable: true, dataGap: null, usesServiceRole: false, via: [], tables: ["projects"], ...over }) as RouteFact;

describe("permission gaps in ranking and coverage", () => {
  it("rank a scoped, signed-in route with a gap ahead of plain scoped routes", () => {
    const ranked = rankRoutes([r({ path: "/api/a" }), r({ path: "/api/import", file: gap.file, permissionGaps: [gap] })]);
    expect(ranked[0].path).toBe("/api/import");
  });
  it("count as risky when the reasoning budget would cut them", () => {
    const routes = [...Array.from({ length: MAX_PROMPT_ROUTES }, (_, i) => r({ path: `/api/a${String(i).padStart(3, "0")}`, ownershipFiltered: false })),
      r({ path: "/api/zz", file: gap.file, permissionGaps: [gap] })];
    expect(riskyRoutesOmitted({ routes, stack: { tools: [], authUnknown: false, databaseUnknown: false }, tables: [], files: [] })).toBe(1);
  });
});

describe("permission gaps become findings from what was read", () => {
  it("renders a WARNING with a manual fix and the witness named", () => {
    const route = r({ path: "/api/import", file: gap.file, permissionGaps: [gap] });
    const witness = r({ path: "/api/projects", file: gap.witness.file });
    const findings = buildFindings({ admitted: [], deterministic: [], routes: [route, witness], repositoryId: "r1", hasDatabase: false,
      stack: { tools: [], authUnknown: false, databaseUnknown: false } });
    expect(findings).toEqual([expect.objectContaining({
      id: "agent:permission_gap:POST:/api/import:project", severity: "WARNING", fixKind: "manual", attackClass: "permission_gap",
      entry: "/api/import", file: gap.file, confidence: "inferred",
    })]);
    const [f] = findings;
    expect(f.title).toBe("POST /api/import changes project records with only tasks.write");
    expect(f.consequence).toContain("projects.write");
    expect(f.consequence).toContain("POST /api/projects");
    expect(`${f.title} ${f.consequence}`).not.toMatch(/[–—]/);
    expect(f.claims.every((c) => c.origin === "routes" && c.verified)).toBe(true);
  });
});

describe("the route inventory attaches gaps", () => {
  it("reads them from the repository's files", () => {
    const h = (method: string, perms: string, body: string) => `export const ${method} = withWorkspace(async () => {\n${body}\n}, { requiredPermissions: [${perms}] });\n`;
    const routes = collectRoutes([
      { path: "app/api/projects/route.ts", content: h("POST", '"projects.write"', "await prisma.project.create({ data: {} });") },
      { path: "app/api/import/route.ts", content: h("POST", '"tasks.write"', "await prisma.project.createMany({ data: [] });") },
    ] as never);
    expect(routes.find((x) => x.file === "app/api/import/route.ts")?.permissionGaps).toEqual([expect.objectContaining({ model: "project", expected: "projects.write" })]);
    expect(routes.find((x) => x.file === "app/api/projects/route.ts")?.permissionGaps ?? []).toEqual([]);
  });
});
