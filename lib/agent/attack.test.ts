import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { buildPrompt, extractJsonArray } from "./attack";
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
