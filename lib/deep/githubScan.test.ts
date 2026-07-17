import { describe, expect, it } from "vitest";
import {
  scanSecrets,
  scanTokenStorage,
  scanLoggedSecrets,
  extractDependencies,
  depFindings,
  type RepoFile,
  type OsvVuln,
} from "./githubScan";

describe("scanSecrets", () => {
  it("flags a committed .env file", () => {
    const f = scanSecrets([{ path: "apps/web/.env.production", content: "X=1" }]);
    expect(f.some((x) => x.id.includes("committed_env"))).toBe(true);
    expect(f[0].severity).toBe("CRITICAL");
  });

  it("flags a PEM private key and a supabase service key", () => {
    const files: RepoFile[] = [
      { path: "key.pem", content: "-----BEGIN RSA PRIVATE KEY-----\nMII...\n" },
      { path: "cfg.ts", content: 'const k = "sb_secret_abcdef1234567890"' },
    ];
    const ids = scanSecrets(files).map((x) => x.id);
    expect(ids.some((i) => i.includes("private_key"))).toBe(true);
    expect(ids.some((i) => i.includes("supabase_service_key"))).toBe(true);
  });

  it("does not flag NEXT_PUBLIC_ assignments", () => {
    const files: RepoFile[] = [
      { path: "env.ts", content: 'const x = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "eyJhbGciOi..."' },
    ];
    expect(scanSecrets(files)).toEqual([]);
  });

  it("is quiet on clean files", () => {
    expect(scanSecrets([{ path: "index.ts", content: "export const x = 1;" }])).toEqual([]);
  });
});

describe("scanLoggedSecrets", () => {
  it("flags logging a sensitive property or interpolated secret", () => {
    const hits: RepoFile[] = [
      { path: "a.ts", content: "console.log(req.headers.authorization)" },
      { path: "b.ts", content: "logger.info(user.password)" },
      { path: "c.ts", content: "console.error(`token=${accessToken}`)" },
    ];
    expect(scanLoggedSecrets(hits).map((f) => f.id.split(":").pop())).toEqual(["a.ts", "b.ts", "c.ts"]);
  });

  it("does not flag the mere word in a message or non-source files", () => {
    const clean: RepoFile[] = [
      { path: "d.ts", content: 'console.log("password required")' },
      { path: "e.ts", content: "console.log(user.email)" },
      { path: "notes.md", content: "console.log(user.password)" },
    ];
    expect(scanLoggedSecrets(clean)).toEqual([]);
  });
});

describe("scanTokenStorage", () => {
  it("flags localStorage supabase-js usage", () => {
    const f = scanTokenStorage([
      { path: "lib/supabase.ts", content: 'import { createClient } from "@supabase/supabase-js";\ncreateClient(a,b)' },
    ]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("WARNING");
  });

  it("stays quiet when the project uses @supabase/ssr", () => {
    const f = scanTokenStorage([
      { path: "lib/a.ts", content: 'import { createClient } from "@supabase/supabase-js"; createClient(a,b)' },
      { path: "lib/b.ts", content: 'import { createServerClient } from "@supabase/ssr";' },
    ]);
    expect(f).toEqual([]);
  });
});

describe("extractDependencies", () => {
  it("prefers exact versions from a v3 lockfile", () => {
    const lock = JSON.stringify({
      packages: { "": { version: "1.0.0" }, "node_modules/next": { version: "16.2.9" } },
    });
    const deps = extractDependencies("{}", lock);
    expect(deps).toContainEqual({ name: "next", version: "16.2.9" });
  });

  it("resolves nested node_modules keys to the real package name", () => {
    const lock = JSON.stringify({
      packages: { "node_modules/a/node_modules/ms": { version: "2.1.3" } },
    });
    const deps = extractDependencies("{}", lock);
    expect(deps).toContainEqual({ name: "ms", version: "2.1.3" });
    expect(deps.some((d) => d.name.includes("node_modules"))).toBe(false);
  });

  it("falls back to package.json ranges when no lockfile", () => {
    const pkg = JSON.stringify({ dependencies: { react: "^19.2.4" }, devDependencies: { vitest: "~4.1.0" } });
    const deps = extractDependencies(pkg, null);
    expect(deps).toContainEqual({ name: "react", version: "19.2.4" });
    expect(deps).toContainEqual({ name: "vitest", version: "4.1.0" });
  });

  it("returns empty on garbage input", () => {
    expect(extractDependencies("not json", "also not json")).toEqual([]);
  });
});

describe("depFindings", () => {
  it("builds one finding per vuln with a stable id", () => {
    const vulns: OsvVuln[] = [{ id: "GHSA-xxxx", cveId: "CVE-2025-0001", summary: "RCE.", severity: "CRITICAL" }];
    const f = depFindings([{ dep: { name: "left-pad", version: "1.0.0" }, vulns }]);
    expect(f).toHaveLength(1);
    expect(f[0].id).toBe("github:dep:left-pad:GHSA-xxxx");
    expect(f[0].packageName).toBe("left-pad");
    expect(f[0].cveId).toBe("CVE-2025-0001");
  });
});
