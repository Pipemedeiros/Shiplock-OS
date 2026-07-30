import { describe, expect, it } from "vitest";
import {
  addSecurityHeaders,
  applyCodemod,
  codemodFor,
  disableProductionSourceMaps,
  hasCodemod,
  renamePublicSecret,
} from "./codemods";
import type { FixableFinding } from "./lane";

const f = (id: string, title = "t"): FixableFinding => ({
  id, source: "scan", title, severity: "WARNING", fix: "x",
});

const NEXT_CONFIG = `import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
};

export default nextConfig;`;

describe("security headers", () => {
  it("adds the standard headers to a next config", () => {
    const out = addSecurityHeaders({ path: "next.config.ts", content: NEXT_CONFIG }, f("scan:x"))!;
    expect(out.content).toContain("X-Content-Type-Options");
    expect(out.content).toContain("Strict-Transport-Security");
    expect(out.content).toContain("reactStrictMode: true"); // preserved
  });

  // A static CSP silently breaks every button on the site (CLAUDE.md).
  it("NEVER adds a Content-Security-Policy — that needs a per-request nonce", () => {
    const out = addSecurityHeaders({ path: "next.config.ts", content: NEXT_CONFIG }, f("scan:x"))!;
    expect(out.content).not.toContain("Content-Security-Policy");
  });

  it("does nothing when the headers are already present", () => {
    const already = NEXT_CONFIG.replace("reactStrictMode: true,", 'headersDone: "X-Content-Type-Options",');
    expect(addSecurityHeaders({ path: "next.config.ts", content: already }, f("scan:x"))).toBeNull();
  });

  // Merging into an existing headers() is a judgement call about ordering.
  it("refuses rather than mangle an existing headers() function", () => {
    const existing = NEXT_CONFIG.replace("reactStrictMode: true,", "async headers() { return []; },");
    expect(addSecurityHeaders({ path: "next.config.ts", content: existing }, f("scan:x"))).toBeNull();
  });

  it("ignores files that are not a next config", () => {
    expect(addSecurityHeaders({ path: "lib/x.ts", content: NEXT_CONFIG }, f("scan:x"))).toBeNull();
  });
});

describe("public-prefixed secret rename", () => {
  const mod = renamePublicSecret("NEXT_PUBLIC_STRIPE_SECRET_KEY");

  it("renames every occurrence", () => {
    const out = mod({ path: "lib/a.ts", content: "process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY + NEXT_PUBLIC_STRIPE_SECRET_KEY" }, f("x"))!;
    expect(out.content).not.toContain("NEXT_PUBLIC_STRIPE_SECRET_KEY");
    expect(out.content).toContain("STRIPE_SECRET_KEY");
  });

  it("does not catch a longer name that merely starts the same", () => {
    const m = renamePublicSecret("NEXT_PUBLIC_API_KEY");
    const out = m({ path: "a.ts", content: "NEXT_PUBLIC_API_KEY_ID" }, f("x"));
    expect(out).toBeNull();
  });

  it("says plainly that it does not rotate the key", () => {
    const out = mod({ path: "a.ts", content: "NEXT_PUBLIC_STRIPE_SECRET_KEY" }, f("x"))!;
    expect(out.description).toContain("no longer inlined");
  });

  it("returns null for files that do not mention it", () => {
    expect(mod({ path: "a.ts", content: "const x = 1;" }, f("x"))).toBeNull();
  });
});

describe("production source maps", () => {
  it("flips the flag to false", () => {
    const out = disableProductionSourceMaps(
      { path: "next.config.ts", content: "const c = { productionBrowserSourceMaps: true };" },
      f("bundle:source_map_exposed:with_content")
    )!;
    expect(out.content).toContain("productionBrowserSourceMaps: false");
  });

  it("does nothing when the flag is absent — the maps come from elsewhere", () => {
    expect(
      disableProductionSourceMaps({ path: "next.config.ts", content: NEXT_CONFIG }, f("bundle:source_map_exposed"))
    ).toBeNull();
  });
});

describe("dispatch — null is the correct answer for judgement cases", () => {
  it("has a codemod for the mechanical fixes", () => {
    expect(hasCodemod(f("scan:missing-security-headers", "Missing security headers"))).toBe(true);
    expect(hasCodemod(f("bundle:source_map_exposed:with_content"))).toBe(true);
    expect(hasCodemod(f("acme/app::github:public_prefixed_secret:NEXT_PUBLIC_X_SECRET:.env"))).toBe(true);
  });

  // Application logic is never machine-authored (CLAUDE.md).
  it("has NO codemod for anything requiring judgement about intent", () => {
    for (const id of [
      "acme/app::github:injection:sql_injection:a.ts",
      "acme/app::github:xss_sink:eval_call:a.tsx",
      "acme/app::github:client_server_secret:a.tsx",
      "path:tenant_isolation:/api/x:public.invoices",
      "proven:tenant_isolation:public.invoices",
      "runtime:credential_stuffing:src-a",
    ]) {
      expect(hasCodemod(f(id)), id).toBe(false);
    }
  });

  it("handles repo-namespaced ids", () => {
    expect(codemodFor(f("acme/app::bundle:source_map_exposed:with_content"))).not.toBeNull();
  });
});

describe("applyCodemod", () => {
  it("returns only the files it actually changed", () => {
    const { results } = applyCodemod(f("bundle:source_map_exposed"), [
      { path: "next.config.ts", content: "const c = { productionBrowserSourceMaps: true };" },
      { path: "lib/x.ts", content: "const x = 1;" },
    ]);
    expect(results).toHaveLength(1);
    expect(results[0].path).toBe("next.config.ts");
  });

  // A half-applied codemod is worse than none.
  it("returns nothing when the transform cannot find what it expects", () => {
    const { results } = applyCodemod(f("bundle:source_map_exposed"), [
      { path: "next.config.ts", content: NEXT_CONFIG },
    ]);
    expect(results).toEqual([]);
  });

  it("returns nothing for a finding with no codemod", () => {
    expect(applyCodemod(f("acme/app::github:injection:sql:a.ts"), [{ path: "a.ts", content: "x" }]).results).toEqual([]);
  });
});
