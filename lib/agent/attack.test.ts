import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { MAX_PROMPT_ROUTES, buildPrompt, extractJsonArray, rankRoutes, routesOmitted } from "./attack";
import type { StackReport } from "./stack";

const route = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/x",
  file: "app/api/x/route.ts",
  methods: ["GET"],
  tables: [],
  authenticated: false,
  machineGated: false,
  usesServiceRole: false,
  ownershipFiltered: false,
  isApiRoute: true,
  via: [],
  ...over,
});

const stack: StackReport = {
  tools: [{ id: "clerk", name: "Clerk", kind: "auth", evidence: "package.json", usedIn: [] }],
  authUnknown: false,
  databaseUnknown: true,
};

describe("buildPrompt", () => {
  it("describes only routes that reach data", () => {
    // A route touching no table cannot leak one. Spending prompt on it crowds
    // out the routes that can, which is how recall gets quietly worse.
    const prompt = buildPrompt({
      routes: [route({ path: "/api/health", tables: [] }), route({ path: "/api/invoices", tables: ["invoices"] })],
      stack,
      tables: ["invoices"],
      files: [],
    });

    expect(prompt).toContain("/api/invoices");
    expect(prompt).not.toContain("/api/health");
  });

  it("states identity and scoping for each route, which is what the model reasons over", () => {
    const prompt = buildPrompt({
      routes: [route({ path: "/api/invoices", tables: ["invoices"], authenticated: true, ownershipFiltered: false })],
      stack,
      tables: ["invoices"],
      files: [],
    });

    expect(prompt).toContain("id=user");
    expect(prompt).toContain("unscoped");
  });

  it("says the stack is unidentified rather than omitting the line", () => {
    const prompt = buildPrompt({
      routes: [route({ tables: ["t"] })],
      stack: { tools: [], authUnknown: true, databaseUnknown: true },
      tables: ["t"],
      files: [],
    });
    expect(prompt).toContain("stack unidentified");
  });
});

describe("extractJsonArray", () => {
  it("reads a bare array", () => {
    expect(extractJsonArray('[{"entry":"/a"}]')).toEqual([{ entry: "/a" }]);
  });

  it("reads an array wrapped in a markdown fence", () => {
    expect(extractJsonArray('```json\n[{"entry":"/a"}]\n```')).toEqual([{ entry: "/a" }]);
  });

  it("returns null for prose, so the caller can record a parse failure", () => {
    // Never [] -- an unparseable answer must not be indistinguishable from a
    // clean result.
    expect(extractJsonArray("I did not find anything obvious.")).toBeNull();
  });

  it("returns null for a truncated array rather than guessing at the rest", () => {
    expect(extractJsonArray('[{"entry":"/a"')).toBeNull();
  });
});

describe("what survives truncation", () => {
  const r = (over: Partial<RouteFact>): RouteFact =>
    ({
      path: "/api/x", file: "app/api/x/route.ts", methods: ["GET"],
      authenticated: true, machineGated: false, ownershipFiltered: true,
      tables: ["things"], ...over,
    }) as RouteFact;

  const emptyStack: StackReport = { tools: [], authUnknown: false, databaseUnknown: false };

  it("puts the open door first and the safe route last", () => {
    const ranked = rankRoutes(
      [
        r({ path: "/api/safe", ownershipFiltered: true }),
        r({ path: "/api/open", authenticated: false, ownershipFiltered: false, tables: ["invoices"] }),
        r({ path: "/api/tenant", authenticated: true, ownershipFiltered: false, tables: ["invoices"] }),
      ],
      new Set(["invoices"]),
    );
    expect(ranked.map((r) => r.path)).toEqual(["/api/open", "/api/tenant", "/api/safe"]);
  });

  it("keeps the riskiest route when there are more than fit", () => {
    // Which routes the agent never sees used to be decided by the order the tar
    // file happened to be in. An anonymous unscoped route could be invisible
    // because its filename sorted late.
    const many = Array.from({ length: MAX_PROMPT_ROUTES + 20 }, (_, i) =>
      r({ path: `/api/scoped-${String(i).padStart(3, "0")}` }),
    );
    const dangerous = r({
      path: "/api/zzz-last-alphabetically",
      authenticated: false,
      ownershipFiltered: false,
      tables: ["invoices"],
    });
    const prompt = buildPrompt({ routes: [...many, dangerous], stack: emptyStack, tables: ["invoices"], files: [] });
    expect(prompt).toContain("/api/zzz-last-alphabetically");
  });

  it("is stable across runs, so a finding does not flicker", () => {
    const routes = [r({ path: "/api/b" }), r({ path: "/api/a" })];
    expect(rankRoutes(routes).map((r) => r.path)).toEqual(rankRoutes([...routes].reverse()).map((r) => r.path));
  });

  it("counts what did not fit, so coverage can say so", () => {
    const many = Array.from({ length: MAX_PROMPT_ROUTES + 7 }, (_, i) => r({ path: `/api/${i}` }));
    expect(routesOmitted({ routes: many, stack: emptyStack, tables: [], files: [] })).toBe(7);
  });
});
