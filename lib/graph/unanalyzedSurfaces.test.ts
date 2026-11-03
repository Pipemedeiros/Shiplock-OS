import { describe, expect, it } from "vitest";
import { countUnanalyzedSurfaces } from "./unanalyzedSurfaces";
import { buildCoverage } from "@/lib/agent/audit";

// Server actions and tRPC procedures can change data, and the deep
// analysis reads route handlers only. Unread must be said, never implied clean.
const f = (path: string, content: string) => ({ path, content });

describe("countUnanalyzedSurfaces", () => {
  it("counts files that define server actions or tRPC procedures", () => {
    expect(countUnanalyzedSurfaces([
      f("app/actions/survey.ts", '"use server";\nexport async function updateSurvey() {}'),
      f("app/(app)/settings/actions.ts", "'use server'\nexport const x = 1;"),
      f("app/page.tsx", 'export default function P() { async function save() { "use server"; } }'),
      f("server/routers/team.ts", "export const teamRouter = createTRPCRouter({ update: protectedProcedure.mutation(() => {}) });"),
      f("server/trpc.ts", "export const publicProcedure = t.procedure;"),
      f("app/api/x/route.ts", "export async function POST() {}"),
      f("lib/util.ts", "const s = 'use server is a directive';"),
      f("node_modules/pkg/index.ts", '"use server";'),
    ])).toEqual({ serverActionFiles: 3, trpcFiles: 2 });
  });
  it("is zero for a routes-only app", () => {
    expect(countUnanalyzedSurfaces([f("app/api/x/route.ts", "export async function GET() {}")])).toEqual({ serverActionFiles: 0, trpcFiles: 0 });
  });
});

describe("Coverage states the unread surfaces", () => {
  const stack = { tools: [], authUnknown: false, databaseUnknown: false };
  it("adds a note with the counts when there are any", () => {
    const notes = buildCoverage(stack, false, 0, true, 0, 0, [], false, false, [], false, [], false, { serverActionFiles: 66, trpcFiles: 0 });
    const note = notes.find((n) => n.name === "Server actions and tRPC procedures");
    expect(note?.why).toContain("66 files define server actions");
    expect(note?.effect).toMatch(/unknown, not clean/);
    expect(`${note?.why} ${note?.effect}`).not.toMatch(/[–—]/);
  });
  it("adds nothing when there are none", () => {
    const notes = buildCoverage(stack, false, 0, true, 0, 0, [], false, false, [], false, [], false, { serverActionFiles: 0, trpcFiles: 0 });
    expect(notes.find((n) => n.name === "Server actions and tRPC procedures")).toBeUndefined();
  });
});

describe("with server actions analyzed, only what is still unread is disclosed", () => {
  const stack = { tools: [], authUnknown: false, databaseUnknown: false };
  it("says analyzed entry actions are covered and names the rest", () => {
    const notes = buildCoverage(stack, false, 0, true, 0, 0, [], false, false, [], false, [], false, { serverActionFiles: 10, trpcFiles: 4, analyzedActions: 7 });
    const note = notes.find((n) => n.name === "Server actions and tRPC procedures");
    expect(note?.why).toContain("7 server actions the browser can call were analyzed like routes");
    expect(note?.why).toContain("4 files define tRPC procedures");
  });
});

describe("with tRPC analyzed, analyzed tRPC procedures leave the unread list", () => {
  const stack = { tools: [], authUnknown: false, databaseUnknown: false };
  const note = (u: Parameters<typeof buildCoverage>[13]) =>
    buildCoverage(stack, false, 0, true, 0, 0, [], false, false, [], false, [], false, u).find((n) => n.name === "Server actions and tRPC procedures");
  it("names analyzed procedures and says router exposure was assumed, not traced", () => {
    const n = note({ serverActionFiles: 0, trpcFiles: 39, analyzedActions: 0, analyzedProcedures: 161 });
    expect(n?.why).toContain("161 tRPC procedures were analyzed like routes");
    expect(n?.why).toMatch(/treated as reachable/);
    expect(n?.why).not.toMatch(/tRPC procedures were not/);
    expect(`${n?.why} ${n?.effect}`).not.toMatch(/[–—]/);
  });
  it("still says tRPC was not read when none of its procedures could be", () => {
    const n = note({ serverActionFiles: 3, trpcFiles: 4, analyzedActions: 2, analyzedProcedures: 0 });
    expect(n?.why).toContain("2 server actions the browser can call were analyzed like routes");
    expect(n?.why).toMatch(/tRPC procedures were not/);
  });
  it("names both kinds when both were analyzed", () => {
    const n = note({ serverActionFiles: 19, trpcFiles: 5, analyzedActions: 55, analyzedProcedures: 34 });
    expect(n?.why).toContain("55 server actions the browser can call and 34 tRPC procedures were analyzed like routes");
    expect(n?.why).toContain("server-only helpers were not");
  });
});
