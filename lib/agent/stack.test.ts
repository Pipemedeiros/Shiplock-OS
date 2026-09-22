import { describe, expect, it } from "vitest";
import { detectStack, readDependencies, routeAnalysisSupport } from "./stack";

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

describe("routeAnalysisSupport", () => {
  it("allows the implemented Next.js route reasoner", () => {
    expect(routeAnalysisSupport(detectStack([pkg({ next: "15.0.0" })]))).toMatchObject({
      level: "deep",
      framework: "nextjs",
    });
  });

  it("keeps detected non-Next frameworks at inventory-only coverage", () => {
    const support = routeAnalysisSupport(detectStack([pkg({ express: "5.0.0" })]));
    expect(support.level).toBe("inventory_only");
    expect(support.reason).toContain("Next.js");
  });
});

describe("the categories the ICP actually runs", () => {
  // Weighted by the Supabase State of Startups 2026 survey rather than by
  // familiarity. Clerk is 4% of this market; Supabase Auth is 72%.

  it("names the AI provider, a category that did not exist before", () => {
    // 64% of this ICP uses Anthropic, 52% OpenAI. A committed provider key is
    // billing theft, and we could not previously even name the vendor.
    const report = detectStack([
      pkg({ "@anthropic-ai/sdk": "^0.30.0", openai: "^4.0.0" }),
      { path: "lib/analyzer.ts", content: 'import Anthropic from "@anthropic-ai/sdk";' },
    ]);
    expect(report.tools.find((t) => t.id === "anthropic")?.kind).toBe("ai");
    expect(report.tools.find((t) => t.id === "openai")?.kind).toBe("ai");
  });

  it("identifies the host from a config file when nothing else names it", () => {
    // A repository deployed on Vercel usually imports no Vercel package and
    // sets no VERCEL_ variable, because the platform injects them at build
    // time. Without this signal, hosting reads as unknown on an app that
    // plainly has a host.
    const report = detectStack([
      pkg({ next: "15.0.0" }),
      { path: "vercel.json", content: '{"framework":"nextjs"}' },
    ]);
    const vercel = report.tools.find((t) => t.id === "vercel");
    expect(vercel?.kind).toBe("hosting");
    expect(vercel?.evidence).toContain("vercel.json");
  });

  it("identifies each host by its own config file", () => {
    for (const [file, id] of [
      ["netlify.toml", "netlify"],
      ["fly.toml", "fly"],
      ["render.yaml", "render"],
      ["wrangler.toml", "cloudflare"],
      ["railway.json", "railway"],
    ] as const) {
      const report = detectStack([pkg({ next: "15.0.0" }), { path: file, content: "" }]);
      expect(report.tools.find((t) => t.id === id), `${file} should identify ${id}`).toBeTruthy();
    }
  });

  it("covers the auth providers this market actually uses", () => {
    const report = detectStack([
      pkg({ "@supabase/ssr": "^0.5.0" }),
      { path: "lib/auth.ts", content: 'import { createServerClient } from "@supabase/ssr";' },
    ]);
    // 72% of the ICP. It must never be missed in favour of a 4% vendor.
    expect(report.tools.find((t) => t.id === "supabase-auth")).toBeTruthy();
    expect(report.authUnknown).toBe(false);
  });

  it("reports auth as unknown rather than absent when nothing matches", () => {
    // 11% of this ICP hand-rolls auth. An empty category must not render as
    // "this app has no authentication".
    const report = detectStack([pkg({ next: "15.0.0" })]);
    expect(report.authUnknown).toBe(true);
    expect(report.tools.some((t) => t.kind === "auth")).toBe(false);
  });

  it("does not invent a host from a mention of one", () => {
    // The substring bug that reported seven auth providers, in a new category.
    const report = detectStack([
      pkg({ next: "15.0.0" }),
      { path: "README.md", content: "Deploy to Netlify or Fly.io or Render" },
      { path: "lib/notes.ts", content: '// we used to run on railway.json before' },
    ]);
    expect(report.tools.filter((t) => t.kind === "hosting")).toHaveLength(0);
  });
});
