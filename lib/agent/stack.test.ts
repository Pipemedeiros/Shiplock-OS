import { describe, expect, it } from "vitest";
import { detectStack, readDependencies } from "./stack";

const pkg = (deps: Record<string, string>) => ({
  path: "package.json",
  content: JSON.stringify({ dependencies: deps }),
});

describe("detectStack", () => {
  it("identifies the auth provider from the manifest and says where it is used", () => {
    const report = detectStack([
      pkg({ "@clerk/nextjs": "^5.0.0", next: "15.0.0" }),
      { path: "app/api/invoices/route.ts", content: 'import { auth } from "@clerk/nextjs/server";' },
    ]);

    const clerk = report.tools.find((t) => t.id === "clerk");
    expect(clerk?.kind).toBe("auth");
    expect(clerk?.evidence).toContain("package.json");
    expect(clerk?.usedIn).toEqual(["app/api/invoices/route.ts"]);
    expect(report.authUnknown).toBe(false);
  });

  it("says so when a dependency is declared but never imported", () => {
    // An auth package nobody imports is usually a half-finished migration, and
    // that is worth reading on the coverage screen rather than smoothing over.
    const report = detectStack([pkg({ "next-auth": "^4.0.0" })]);
    expect(report.tools.find((t) => t.id === "nextauth")?.evidence).toContain("not imported anywhere");
  });

  it("detects a tool that has no package, from its environment variables", () => {
    const report = detectStack([
      pkg({ next: "15.0.0" }),
      { path: ".env.example", content: "R2_ACCOUNT_ID=\nR2_ACCESS_KEY_ID=" },
    ]);
    expect(report.tools.find((t) => t.id === "r2")?.evidence).toBe("named in an environment file");
  });

  it("reports an unknown stack as unknown, never as empty", () => {
    // The distinction the whole product rests on: we did not identify it is a
    // different claim from there is nothing there.
    const report = detectStack([pkg({ lodash: "^4.0.0" })]);
    expect(report.tools).toEqual([]);
    expect(report.authUnknown).toBe(true);
    expect(report.databaseUnknown).toBe(true);
  });

  it("survives a malformed package.json without losing import-based detection", () => {
    const report = detectStack([
      { path: "package.json", content: "{ this is not json" },
      { path: "lib/db.ts", content: 'import { createClient } from "@supabase/supabase-js";' },
    ]);
    expect(report.tools.find((t) => t.id === "supabase")).toBeDefined();
  });
});

describe("false positives found by running this against ShipLock's own repository", () => {
  it("does not count a package name that merely appears in a string", () => {
    // The first dogfood run reported Clerk, Auth0, Lucia, WorkOS, Prisma,
    // MongoDB and Firebase on a codebase using none of them -- every one of
    // them from the signature list inside stack.ts itself. Substring matching
    // turns any repository that NAMES a library into one that depends on it.
    const report = detectStack([
      pkg({ next: "15.0.0" }),
      { path: "docs/comparison.ts", content: 'const options = ["@clerk/nextjs", "next-auth", "lucia"];' },
    ]);
    expect(report.tools.map((t) => t.id)).toEqual(["next"]);
  });

  it("ignores test files, which mention libraries they do not use", () => {
    const report = detectStack([
      pkg({ next: "15.0.0" }),
      { path: "lib/auth.test.ts", content: 'vi.mock("@clerk/nextjs", () => ({}));' },
    ]);
    expect(report.tools.find((t) => t.id === "clerk")).toBeUndefined();
  });

  it("still counts a real import, including a subpath", () => {
    const report = detectStack([
      pkg({}),
      { path: "app/page.tsx", content: 'import { auth } from "@clerk/nextjs/server";' },
    ]);
    expect(report.tools.find((t) => t.id === "clerk")).toBeDefined();
  });
});

describe("readDependencies", () => {
  it("reads dev dependencies too", () => {
    const deps = readDependencies(JSON.stringify({ dependencies: { a: "1" }, devDependencies: { b: "2" } }));
    expect([...deps].sort()).toEqual(["a", "b"]);
  });

  it("returns empty for a missing manifest rather than throwing", () => {
    expect(readDependencies(undefined).size).toBe(0);
  });
});
