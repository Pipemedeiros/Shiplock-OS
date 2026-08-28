import { describe, expect, it } from "vitest";
import {
  scanSecrets,
  isTestPath,
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

  it("does not flag LLM token COUNTS (input_tokens/output_tokens)", () => {
    const counts: RepoFile[] = [
      { path: "a.ts", content: "console.log(`model=${m} input_tokens=${res.usage.input_tokens} output_tokens=${res.usage.output_tokens}`)" },
    ];
    expect(scanLoggedSecrets(counts)).toEqual([]);
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
    const vulns: OsvVuln[] = [
      { id: "GHSA-xxxx", cveId: "CVE-2025-0001", summary: "RCE.", severity: "CRITICAL", fixedVersion: "1.0.1" },
    ];
    const f = depFindings([{ dep: { name: "left-pad", version: "1.0.0" }, vulns }]);
    expect(f).toHaveLength(1);
    expect(f[0].id).toBe("github:dep:left-pad:GHSA-xxxx");
    expect(f[0].packageName).toBe("left-pad");
    expect(f[0].cveId).toBe("CVE-2025-0001");
  });
});

describe("fixtures are not leaks", () => {
  const REAL_LOOKING = "sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5";

  it("does not report a synthetic key in a test file", () => {
    // The failure this exists to stop: auditing our own repository produced
    // fifteen criticals, every one a fake credential inside a detector's own
    // fixtures. One wrong critical costs more trust than five right ones earn.
    const findings = scanSecrets([
      { path: "lib/deep/githubScan.test.ts", content: 'const key = "AKIAIOSFODNN7EXAMPLE";' },
      { path: "lib/security/x.test.ts", content: 'const k = "sb_secret_example_not_a_real_key";' },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("still reports a real-looking key in a test file, one step quieter", () => {
    // A suite that authenticates against a live sandbox needs a real key, and
    // that key is in source control. Quieter, not silent.
    const findings = scanSecrets([
      { path: "lib/deep/thing.test.ts", content: `const key = "${REAL_LOOKING}";` },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("WARNING");
    expect(findings[0].title).toContain("test file");
  });

  it("never downgrades a key in shipped code, however it is spelled", () => {
    const findings = scanSecrets([
      { path: "lib/deep/thing.ts", content: `const key = "${REAL_LOOKING}";` },
    ]);
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("reports a synthetic-looking value in shipped code — it is real code either way", () => {
    const findings = scanSecrets([
      { path: "app/api/x/route.ts", content: 'const k = "AKIAIOSFODNN7EXAMPLE";' },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("recognises the shapes of test scaffolding", () => {
    for (const p of [
      "lib/x.test.ts", "lib/x.spec.tsx", "__tests__/x.ts", "test/helpers.ts",
      "tests/x.ts", "src/__mocks__/db.ts", "fixtures/repo.ts", "vitest.config.ts",
    ]) expect(isTestPath(p)).toBe(true);
    for (const p of [
      "lib/scanner.ts", "app/api/scan/route.ts", "lib/latest.ts", "components/Contest.tsx",
    ]) expect(isTestPath(p)).toBe(false);
  });

  it("treats a placeholder that spells the alphabet as the placeholder it is", () => {
    const findings = scanSecrets([
      { path: "lib/deep/x.test.ts", content: 'const k = "sb_secret_abcdefghijklmno";' },
      { path: "lib/deep/y.test.ts", content: 'const k = "sb_secret_AbCdEfGhIjKlMnOp";' },
      { path: "vitest.config.ts", content: 'SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",' },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does not treat a generic assignment in test scaffolding as a credential", () => {
    // The generic pattern proves only that something was assigned to a name
    // containing SECRET. The vendor-shaped patterns still apply here.
    const findings = scanSecrets([
      { path: "lib/deep/vercel.test.ts", content: 'VERCEL_CLIENT_SECRET: "client-secret-456",' },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does not mistake a token COUNT for a token", () => {
    // Our own [TOKENS] efficiency log line was reported as a leaked secret.
    const findings = scanLoggedSecrets([
      { path: "lib/graph/narrative.ts", content: "console.log(`[TOKENS] input=${tokensIn} output=${tokensOut}`);" },
      { path: "lib/a.ts", content: "console.log(`used ${tokens} of ${maxTokens}`);" },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("still reports an actual token being logged", () => {
    const findings = scanLoggedSecrets([
      { path: "lib/b.ts", content: "console.log(`session ${accessToken}`);" },
      { path: "lib/c.ts", content: "console.log(`refresh ${refreshToken}`);" },
    ]);
    expect(findings).toHaveLength(2);
  });

  it("does not report a placeholder written into a comment", () => {
    // githubScan.ts reported its own explanatory comment as a leaked AWS key.
    const findings = scanSecrets([
      { path: "lib/deep/githubScan.ts", content: "// AKIAIOSFODNN7EXAMPLE is Amazon's own published example\nconst x = 1;" },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("still reports a real-looking key in a comment — people paste those", () => {
    const findings = scanSecrets([
      { path: "lib/a.ts", content: "// old key: sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5\nconst x = 1;" },
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("does not report a logged secret inside a test", () => {
    const findings = scanLoggedSecrets([
      { path: "lib/redact.test.ts", content: "console.log(user.password);" },
    ]);
    expect(findings).toHaveLength(0);
  });
});
