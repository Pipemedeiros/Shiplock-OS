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

describe("findPermissionGaps: Pages API", () => {
  // Mirrors the corpus-b idiom: `const xHandler = withTeamApi(fn, { requiredPermissions })`
  // per method, dispatched by an `export default function handle(req, res)` on req.method.
  const pagesHandler = (name: string, perms: string[], body: string) =>
    `const ${name}Handler = withTeamApi(\n  async ({ req, res }) => {\n${body}\n  },\n  { requiredPermissions: [${perms.map((p) => `"${p}"`).join(", ")}] },\n);\n\n`;
  const dispatch = (methods: [string, string][]) =>
    "export default async function handle(req, res) {\n" +
    methods.map(([m, name]) => `  if (req.method === "${m}") {\n    return ${name}Handler(req, res);\n  }\n`).join("") +
    "}\n";

  it("flags a Pages API handler that writes a model another handler guards with that model's permission", () => {
    const brandRoute = route("pages/api/teams/[teamId]/brands/[brandId]/index.ts",
      pagesHandler("get", ["branding.read"], "return res.status(200).json(brand);") +
      pagesHandler("put", ["brands.write"], "await prisma.brand.update({ where: {}, data: {} });") +
      dispatch([["GET", "get"], ["PUT", "put"]]));
    const brandsIndex = route("pages/api/teams/[teamId]/brands/index.ts",
      pagesHandler("post", ["branding.write"], "await prisma.brand.create({ data: {} });") +
      dispatch([["POST", "post"]]));
    expect(findPermissionGaps([brandRoute, brandsIndex])).toEqual([{
      file: "pages/api/teams/[teamId]/brands/index.ts", method: "POST", model: "brand", requires: ["branding.write"],
      expected: "brands.write", witness: { file: "pages/api/teams/[teamId]/brands/[brandId]/index.ts", method: "PUT" }, tier: "declared",
    }]);
  });

  it("skips a default export that branches on req.method inline for more than one method", () => {
    const withGuard = route("pages/api/teams/[teamId]/brands/index.ts",
      pagesHandler("post", ["brands.write"], "await prisma.brand.create({ data: {} });") + dispatch([["POST", "post"]]));
    const inline = route("pages/api/teams/[teamId]/datarooms/[id]/members.ts",
      "export default withTeamApi(\n  async ({ req, res, role }) => {\n" +
      "    if (req.method === \"GET\") {\n      return res.status(200).json([]);\n    }\n" +
      "    if (req.method === \"DELETE\") {\n      await prisma.brand.deleteMany({ where: {} });\n      return res.status(204).end();\n    }\n" +
      "  },\n  { requiredPermissions: [\"branding.read\"] },\n);\n");
    expect(findPermissionGaps([withGuard, inline])).toEqual([]);
  });

  it("reads a single-method inline default export", () => {
    const inline = route("pages/api/teams/[teamId]/datarooms/[id]/duplicate.ts",
      "export default withTeamApi(\n  async ({ req, res }) => {\n" +
      "    if (req.method === \"POST\") {\n      await prisma.dataroom.create({ data: {} });\n    }\n" +
      "  },\n  { requiredPermissions: [\"datarooms.read\"] },\n);\n");
    const witness = route("pages/api/teams/[teamId]/datarooms/index.ts",
      pagesHandler("post", ["datarooms.write"], "await prisma.dataroom.create({ data: {} });") + dispatch([["POST", "post"]]));
    expect(findPermissionGaps([inline, witness]).map((g) => [g.file, g.method, g.model])).toEqual([
      ["pages/api/teams/[teamId]/datarooms/[id]/duplicate.ts", "POST", "dataroom"],
    ]);
  });

  it("ignores Pages API files outside pages/api, and non-route files inside it", () => {
    const outside = route("lib/pages/api-helpers.ts", pagesHandler("post", ["tasks.write"], "await prisma.project.create({ data: {} });") + dispatch([["POST", "post"]]));
    expect(findPermissionGaps([projectsCreate, outside])).toEqual([]);
  });
});
