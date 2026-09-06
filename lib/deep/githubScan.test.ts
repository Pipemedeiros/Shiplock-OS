import { describe, expect, it } from "vitest";
import {
  scanSecrets,
  looksSynthetic,
  isTestPath,
  scanTokenStorage,
  scanLoggedSecrets,
  extractDependencies,
  depFindings,
  type RepoFile,
  type OsvVuln,
} from "./githubScan";

describe("scanSecrets", () => {
  it("flags a committed .env file that carries a real value", () => {
    const f = scanSecrets([
      { path: "apps/web/.env.production", content: 'DATABASE_PASSWORD="hunter2GoesHereAndIsLong"' },
    ]);
    expect(f.some((x) => x.id.includes("committed_env"))).toBe(true);
    expect(f[0].severity).toBe("CRITICAL");
  });

  it("flags a committed .env holding nothing real as a warning, not an emergency", () => {
    // Severity has to keep meaning something. A committed env file with no
    // filled-in value is a habit worth breaking, not a leak.
    const f = scanSecrets([{ path: "apps/web/.env.production", content: "X=1" }]);
    expect(f[0].severity).toBe("WARNING");
  });

  it("does not call a project name a credential", () => {
    // A 7,000-star boilerplate's committed .env.production was reported
    // CRITICAL for setting a project name and a contact email address.
    const f = scanSecrets([
      {
        path: ".env.production",
        content: "CHECKLY_EMAIL_ADDRESS=contact@example.com\nCHECKLY_PROJECT_NAME=SaaS Boilerplate\nCHECKLY_LOGICAL_ID=saas-boilerplate",
      },
    ]);
    expect(f[0].severity).toBe("WARNING");
  });

  it("does not call a localhost database url a credential", () => {
    const f = scanSecrets([
      { path: ".env", content: "DATABASE_URL=postgresql://postgres@localhost:5432/app" },
    ]);
    expect(f[0].severity).toBe("WARNING");
  });

  it("still calls a filled-in credential key what it is", () => {
    const f = scanSecrets([
      { path: ".env", content: "DATABASE_URL=postgresql://admin:Hunter2Hunter2@db.prod.example.com:5432/app" },
    ]);
    expect(f[0].severity).toBe("CRITICAL");
  });

  it("does not report a dev password in a seed script", () => {
    // A starter kit sets ADMIN_PASSWORD to 'admin@123' in prisma/seed.ts.
    // Telling its author to rotate that is noise.
    expect(scanSecrets([{ path: "prisma/seed.ts", content: "const ADMIN_PASSWORD = 'admin@123';" }])).toHaveLength(0);
  });

  it("says nothing about a public-by-design env file", () => {
    // A real Supabase starter commits EXPO_PUBLIC_ values including the anon
    // key, which is meant to ship to the client. Reporting that as a credential
    // leak is the same overreach as flagging a publishable key in a bundle.
    const f = scanSecrets([
      {
        path: "expo/.env",
        content: 'EXPO_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nEXPO_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      },
    ]);
    expect(f[0].severity).toBe("WARNING");
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

  it("does not report a placeholder env file as a hardcoded secret", () => {
    // Auditing corpus-g reported a CRITICAL hardcoded secret in .env.example,
    // which is the file every project is supposed to commit to document its
    // variables.
    const findings = scanSecrets([
      {
        path: ".env.example",
        content: 'NEXTAUTH_SECRET="your-secret-here"\nDATABASE_URL="postgres://user:password@localhost:5432/db"',
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("still reports a real vendor key pasted into a placeholder env file", () => {
    const findings = scanSecrets([
      { path: ".env.example", content: 'SUPABASE_KEY="sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5"' },
    ]);
    expect(findings).toHaveLength(1);
  });

  it("treats any your-* placeholder as the placeholder it is", () => {
    // corpus-g documents its SMTP variable in a JSDoc block as
    // NEXT_PRIVATE_SMTP_PASSWORD='your-password'. The marker list covered
    // your-key, your-token and your-secret but not your-password, so the
    // documentation was reported as a committed credential.
    const findings = scanSecrets([
      {
        path: "packages/email/mailer.ts",
        content: " * NEXT_PRIVATE_SMTP_PASSWORD='your-password';\nconst x = 1;",
      },
    ]);
    expect(findings).toHaveLength(0);
  });

  it("does not report a logged secret inside a test", () => {
    const findings = scanLoggedSecrets([
      { path: "lib/redact.test.ts", content: "console.log(user.password);" },
    ]);
    expect(findings).toHaveLength(0);
  });
});

// BLOCKER 2 (2026-09-06). The stated rule is that the PATH decides how loudly
// we speak and the VALUE decides whether we speak at all. For committed env
// files only the value half was implemented, and the value test never
// consulted looksSynthetic, so placeholders shipped as CRITICAL on three of
// ten validation repositories.
describe("committed env severity follows the stated rule", () => {
  const sev = (path: string, content: string) =>
    scanSecrets([{ path, content }]).find((f) => f.id.startsWith("github:committed_env"))?.severity;

  it("a placeholder that restates its key is not a secret (nocodb)", () => {
    expect(sev("docker-compose/.env", "CF_DNS_API_TOKEN=SOME_CLOUDFLARE_TOKEN\n")).toBe("WARNING");
  });

  it("a plain URL is not a secret even under an AUTH-ish key (corpus-ag)", () => {
    expect(sev("apps/api/.env.development", "CLIENT_SUCCESS_AUTH_REDIRECT=https://dev.web.corpus-ag.co/auth/login\n")).toBe("WARNING");
  });

  it("a synthetic value is not a secret (outline UTILS_SECRET)", () => {
    expect(sev(".env.local", "UTILS_SECRET=test-utils-secret\n")).toBe("WARNING");
  });

  it("a real-looking value in a TEST env file is reported one step quieter", () => {
    expect(sev(".env.test", "SECRET_KEY=F0E5AD933D7F6FD8F4DBB3E038C501C052DC0593C686D21ACB30AE205D2F634B\n")).toBe("WARNING");
  });

  // The trade, and the direction that must not change: still reported.
  it("a real-looking value in a NON-test env file is still CRITICAL", () => {
    expect(sev(".env", "STRIPE_SECRET_KEY=sk_live_51H8xQ2eZvKYlo2C9mMxTr7bN3pQwErTyUiOpAsDfGh\n")).toBe("CRITICAL");
  });

  it("a test env file with a real-looking value is never silent", () => {
    expect(sev(".env.test", "SECRET_KEY=F0E5AD933D7F6FD8F4DBB3E038C501C052DC0593C686D21ACB30AE205D2F634B\n")).toBeDefined();
  });
});

// Three more placeholder shapes, each found by hand-reading a critical the
// 2026-09-06 validation still produced after the first pass.
describe("values that cannot be a usable credential", () => {
  const sev = (path: string, content: string) =>
    scanSecrets([{ path, content }]).find((f) => f.id.startsWith("github:committed_env"))?.severity;

  it("a bcrypt hash is a hash, not a credential (corpus-ag)", () => {
    expect(sev(".env.development", "SOCKET_IO_ADMIN_PASSWORD_HASH=$2b$10$heqvAkYMez.Va6Et2uXInOnkCT6/uQj1brkrbyG3LpopDklcq7ZOS\n")).toBe("WARNING");
  });

  it("a PEM with a body too short to be a key is a placeholder (outline)", () => {
    expect(looksSynthetic(
      '-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA\\n-----END RSA PRIVATE KEY-----',
      'GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA\\n-----END RSA PRIVATE KEY-----"',
    )).toBe(true);
  });

  it("but a full-length PEM body is still a key", () => {
    const body = "MIIEpAIBAAKCAQEA" + "QWxpY2VCb2JDaGFybGll".repeat(12);
    expect(looksSynthetic(`-----BEGIN RSA PRIVATE KEY-----\\n${body}\\n-----END RSA PRIVATE KEY-----`,
      `KEY="-----BEGIN RSA PRIVATE KEY-----\\n${body}\\n-----END RSA PRIVATE KEY-----"`)).toBe(false);
  });
});
