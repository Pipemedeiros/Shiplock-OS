import { describe, expect, it } from "vitest";
import { findPermissionGaps } from "./permissionGaps";

// Step 7C-1: a deterministic "same write, weaker permission" check. Fixtures
// are synthetic; the held-out corpus-a labels are never used to tune this.
const route = (path: string, content: string) => ({ path, content });
const handler = (method: string, perms: string[] | null, body: string, extra = "") =>
  `export const ${method} = withWorkspace(async ({ workspace, req }) => {\n${body}\n}${perms ? `, { requiredPermissions: [${perms.map((p) => `"${p}"`).join(", ")}]${extra} }` : ""});\n`;

const projectsCreate = route("app/api/projects/route.ts", handler("POST", ["projects.write"], "await prisma.project.create({ data: {} });"));
const importer = route("app/api/workspaces/[id]/import/route.ts",
  handler("POST", ["tasks.write"], "await prisma.project.createMany({ data: rows });\nawait prisma.task.createMany({ data: rows });"));
const tasks = route("app/api/tasks/route.ts", handler("POST", ["tasks.write"], "await prisma.task.create({ data: {} });"));

describe("findPermissionGaps", () => {
  it("flags a handler that writes a model another handler guards with that model's permission", () => {
    expect(findPermissionGaps([projectsCreate, importer, tasks])).toEqual([{
      file: "app/api/workspaces/[id]/import/route.ts", method: "POST", model: "project", requires: ["tasks.write"],
      expected: "projects.write", witness: { file: "app/api/projects/route.ts", method: "POST" }, tier: "declared",
    }]);
  });

  it("does not flag when every writer holds the model's permission", () => {
    const ok = route("app/api/projects/bulk/route.ts", handler("POST", ["projects.write", "tasks.write"], "await prisma.project.createMany({ data: [] });"));
    expect(findPermissionGaps([projectsCreate, ok])).toEqual([]);
  });

  it("needs a witness: no route guarding the model means no claim", () => {
    expect(findPermissionGaps([importer, tasks])).toEqual([]);
  });

  it("treats a handler with no readable permission list as neither subject nor witness", () => {
    const open = route("app/api/cron/projects/route.ts", "export const POST = withCron(async () => { await prisma.project.create({ data: {} }); });\n");
    const noPerms = route("app/api/projects/other/route.ts", handler("PATCH", null, "await prisma.project.update({ where: {}, data: {} });"));
    expect(findPermissionGaps([projectsCreate, open, noPerms])).toEqual([]);
  });

  it("skips a handler with its own role check, which may be the stronger gate", () => {
    const roleChecked = route("app/api/workspaces/[id]/import/route.ts",
      handler("POST", ["tasks.write"], "if (workspace.role !== \"owner\") throw new Error();\nawait prisma.project.createMany({ data: rows });"));
    const withRoles = route("app/api/x/route.ts", handler("POST", ["tasks.write"], "await prisma.project.create({ data: {} });", ", requiredRoles: [\"owner\"]"));
    expect(findPermissionGaps([projectsCreate, roleChecked, withRoles])).toEqual([]);
  });

  it("judges each exported handler separately, in both export styles", () => {
    const file = route("app/api/projects/[pid]/route.ts",
      handler("GET", ["tasks.read"], "return prisma.project.findUnique({ where: {} });") +
      "export async function DELETE(req: Request) {\n  return withWorkspace(async () => { await prisma.project.delete({ where: {} }); }, { requiredPermissions: [\"tasks.write\"] })(req);\n}\n");
    expect(findPermissionGaps([projectsCreate, file]).map((g) => [g.file, g.method, g.model])).toEqual([
      ["app/api/projects/[pid]/route.ts", "DELETE", "project"],
    ]);
  });

  it("matches permission resources to models across plural and camelCase forms", () => {
    const apiKeys = route("app/api/tokens/route.ts", handler("POST", ["apiKeys.write"], "await prisma.apiKey.create({ data: {} });"));
    const sneaky = route("app/api/settings/route.ts", handler("POST", ["workspaces.write"], "await prisma.apiKey.create({ data: {} });"));
    expect(findPermissionGaps([apiKeys, sneaky]).map((g) => [g.file, g.expected])).toEqual([["app/api/settings/route.ts", "apiKeys.write"]]);
  });

  it("ignores files that are not route handlers", () => {
    expect(findPermissionGaps([projectsCreate, route("lib/projects.ts", handler("POST", ["tasks.write"], "await prisma.project.create({ data: {} });"))])).toEqual([]);
  });
});

it("does not judge code-level role checks (unsupported, never flagged)", () => {
  const code = (path: string, check: string) => route(path, `export async function PATCH() {\n${check}\nawait prisma.team.update({ where: {}, data: {} });\n}\n`);
  expect(findPermissionGaps([code("app/api/a/route.ts", "if (!isAdmin) return;"), code("app/api/b/route.ts", "if (!isAdmin) return;"),
    code("app/api/c/route.ts", "")])).toEqual([]);
});

it("finds every declared file, not every other one (stateless matching)", () => {
  const writers = Array.from({ length: 4 }, (_, i) => route(`app/api/p${i}/route.ts`, handler("POST", ["projects.write"], "await prisma.project.create({ data: {} });")));
  const weak = Array.from({ length: 4 }, (_, i) => route(`app/api/w${i}/route.ts`, handler("POST", ["tasks.write"], "await prisma.project.create({ data: {} });")));
  expect(findPermissionGaps([...writers, ...weak]).map((g) => g.file)).toEqual(weak.map((w) => w.path));
});
