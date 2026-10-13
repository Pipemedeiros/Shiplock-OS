import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import {
  scanSecrets,
  looksSynthetic,
  isTestPath,
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

  it("states a committed .env holding nothing real as a fact, not an issue", () => {
    // Severity has to keep meaning something. A committed env file with no
    // filled-in value is a habit worth breaking, not a leak; the census of
    // 2026-10-06 found 71 such warnings and none real, so it no longer sets
    // the status.
    const f = scanSecrets([{ path: "apps/web/.env.production", content: "X=1" }]);
    expect(f[0].severity).toBe("INFO");
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
    expect(f[0].severity).toBe("INFO");
  });

  it("does not call a localhost database url a credential", () => {
    const f = scanSecrets([
      { path: ".env", content: "DATABASE_URL=postgresql://postgres@localhost:5432/app" },
    ]);
    expect(f[0].severity).toBe("INFO");
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
    expect(f[0].severity).toBe("INFO");
  });

  it("flags a parseable PEM private key and a supabase service key", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const files: RepoFile[] = [
      { path: "key.pem", content: pem },
      { path: "cfg.ts", content: 'const k = "sb_secret_abcdef1234567890"' },
    ];
    const ids = scanSecrets(files).map((x) => x.id);
    expect(ids.some((i) => i.includes("private_key"))).toBe(true);
    expect(ids.some((i) => i.includes("supabase_service_key"))).toBe(true);
  });

  it("retains generated private keys in raw, escaped, and commented source", () => {
    const pem = generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const variants = [
      pem,
      JSON.stringify({ private_key: pem }),
      `export const key = ${JSON.stringify(pem)};`,
      `// example of the actual committed key\n${pem.split("\n").map((line) => `// ${line}`).join("\n")}`,
      `/*\n${pem.split("\n").map((line) => ` * ${line}`).join("\n")} */`,
      `-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----\n${pem}`,
    ];
    for (const content of variants) {
      expect(scanSecrets([{ path: "config.ts", content }]).map((finding) => finding.id)).toContain("github:secret:private_key:config.ts");
      expect(scanSecrets([{ path: "key.test.ts", content }]).find((finding) => finding.id.includes("private_key"))?.severity).toBe("WARNING");
    }
  });

  it("retains an OpenSSH container holding a generated Ed25519 private key", () => {
    const jwk = generateKeyPairSync("ed25519").privateKey.export({ format: "jwk" });
    const str = (value: string | Buffer) => {
      const body = typeof value === "string" ? Buffer.from(value) : value;
      const length = Buffer.alloc(4); length.writeUInt32BE(body.length);
      return Buffer.concat([length, body]);
    };
    const pub = Buffer.from(jwk.x!, "base64url");
    const priv = Buffer.from(jwk.d!, "base64url");
    const publicSection = Buffer.concat([str("ssh-ed25519"), str(pub)]);
    const checks = Buffer.from("a1b2c3d4a1b2c3d4", "hex");
    const section = Buffer.concat([checks, str("ssh-ed25519"), str(pub), str(Buffer.concat([priv, pub])), str("")]);
    const padding = Buffer.from(Array.from({ length: 8 - section.length % 8 }, (_, i) => i + 1));
    const count = Buffer.from([0, 0, 0, 1]);
    const container = Buffer.concat([Buffer.from("openssh-key-v1\0"), str("none"), str("none"), str(""), count, str(publicSection), str(Buffer.concat([section, padding]))]);
    const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${container.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(scanSecrets([{ path: "deploy.key", content: pem }]).map((finding) => finding.id)).toContain("github:secret:private_key:deploy.key");
  });

  it("retains a generated encrypted RSA PKCS1 key without knowing its passphrase", () => {
    const pem = generateKeyPairSync("rsa", { modulusLength: 1024 }).privateKey.export({ type: "pkcs1", format: "pem", cipher: "aes-256-cbc", passphrase: "fixture-passphrase" }).toString();
    expect(scanSecrets([{ path: "key.pem", content: pem }]).map((finding) => finding.id)).toContain("github:secret:private_key:key.pem");
    expect(scanSecrets([{ path: "config.ts", content: `export const key = ${JSON.stringify(pem)}` }]).map((finding) => finding.id)).toContain("github:secret:private_key:config.ts");
  });

  it("rejects an OpenSSH envelope without an algorithm or key fields", () => {
    const field = (value: Buffer) => { const size = Buffer.alloc(4); size.writeUInt32BE(value.length); return Buffer.concat([size, value]); };
    const data = Buffer.concat([Buffer.from("openssh-key-v1\0"), field(Buffer.from("none")), field(Buffer.from("none")), field(Buffer.alloc(0)), Buffer.from([0, 0, 0, 1]), field(Buffer.alloc(32)), field(Buffer.alloc(64))]);
    expect(scanSecrets([{ path: "key.pem", content: `-----BEGIN OPENSSH PRIVATE KEY-----\n${data.toString("base64")}\n-----END OPENSSH PRIVATE KEY-----` }])).toEqual([]);
  });

  it("does not call a PEM header or truncated example a private key", () => {
    expect(scanSecrets([
      { path: "header.txt", content: "-----BEGIN PRIVATE KEY-----" },
      { path: "example.env", content: "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----" },
    ])).toEqual([]);
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
    expect(sev("docker-compose/.env", "CF_DNS_API_TOKEN=SOME_CLOUDFLARE_TOKEN\n")).toBe("INFO");
  });

  it("a plain URL is not a secret even under an AUTH-ish key (corpus-ag)", () => {
    expect(sev("apps/api/.env.development", "CLIENT_SUCCESS_AUTH_REDIRECT=https://dev.web.corpus-ag.co/auth/login\n")).toBe("INFO");
  });

  it("a synthetic value is not a secret (outline UTILS_SECRET)", () => {
    expect(sev(".env.local", "UTILS_SECRET=test-utils-secret\n")).toBe("INFO");
  });

  // CORPUS-6 (2026-10-06): a value we cannot judge is a fact, not an issue;
  // about 80 such committed env files were read and none held a live one.
  it("a real-looking value in a TEST env file is stated as a fact", () => {
    expect(sev(".env.test", "SECRET_KEY=F0E5AD933D7F6FD8F4DBB3E038C501C052DC0593C686D21ACB30AE205D2F634B\n")).toBe("INFO");
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
    expect(sev(".env.development", "SOCKET_IO_ADMIN_PASSWORD_HASH=$2b$10$heqvAkYMez.Va6Et2uXInOnkCT6/uQj1brkrbyG3LpopDklcq7ZOS\n")).toBe("INFO");
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

// Census 2026-10-06 (docs/evaluation/shown-without-agent-2026-10-06.json): 8 of
// 9 committed-env criticals held no live credential (generator templates, local
// emulator defaults). CRITICAL needs a value shaped like a live credential;
// a value we cannot judge stays a WARNING, never silent.
describe("a committed env file is CRITICAL only with a live credential", () => {
  const find = (path: string, content: string) =>
    scanSecrets([{ path, content }]).find((f) => f.id.startsWith("github:committed_env"));
  const sev = (path: string, content: string) => find(path, content)?.severity;

  it("an inline-credential URL to a hosted database is CRITICAL (corpus-f .env.save)", () => {
    expect(sev(".env.save", "DATABASE_URL=postgresql://app:Zq8vLm2Rt5Xw@ep-gentle-scene-pooler.us-east-2.aws.neon.tech/neondb\n")).toBe("CRITICAL");
  });
  it("a vendor secret shape is CRITICAL in a local env file too", () => {
    expect(sev(".env.local", "SUPABASE_SERVICE_ROLE_KEY=sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5\n")).toBe("CRITICAL");
    expect(sev(".env.development", "STRIPE_SECRET_KEY=sk_live_51H8xQ2eZvKYlo2C9mMxTr7bN3pQwErTyUiOpAsDfGh\n")).toBe("CRITICAL");
  });
  // Found by this census: the shouty-placeholder test (CHANGE_ME_PLEASE) also
  // matched an uppercase hex key, so a real one was dropped as a placeholder.
  it("an uppercase hex key is a value, not a placeholder", () => {
    expect(sev(".env.production", "SECRET_KEY=F0E5AD933D7F6FD8F4DBB3E038C501C052DC0593C686D21ACB30AE205D2F634B\n")).toBe("CRITICAL");
    expect(sev("docker-compose/.env", "CF_DNS_API_TOKEN=SOME_CLOUDFLARE_TOKEN\n")).toBe("INFO");
  });
  // Release run r2 (2026-10-12, both labelers: not accurate, not real): a
  // French-named template, .env.exemple, holding the textbook placeholder
  // URL user:password@host was reported CRITICAL.
  it("a template named in another language is a template (corpus-ah .env.exemple)", () => {
    expect(find(".env.exemple", "DATABASE_URL=\"postgresql://user:password@host:5432/corpus-ah?sslmode=require\"\n")).toBeUndefined();
  });
  it("the textbook placeholder URL user:password@host is not a live credential", () => {
    expect(sev(".env", "DATABASE_URL=\"postgresql://user:password@host:5432/app\"\n")).not.toBe("CRITICAL");
    expect(sev(".env", "DATABASE_URL=postgresql://username:password@hostname/db\n")).not.toBe("CRITICAL");
    expect(sev(".env", "DATABASE_URL=postgresql://app:Zq8vLm2Rt5Xw@host.prod-db.internal/db\n")).toBe("CRITICAL");
  });
  it("a filled secret in a deployed-environment file with no local host is CRITICAL", () => {
    expect(sev(".env.production", "JWT_SECRET=Kq7Lm2Xz8Rt4Bn6Vc1Wd5Fh3Jp9\n")).toBe("CRITICAL");
  });
  it("a local SQLite path in a generator template is a fact (corpus-ae)", () => {
    const f = find("packages/generator/templates/app/.env.local", "# This env file should NOT be checked into source control\nDATABASE_URL=\"file:./db/db.db\"\n");
    expect(f?.severity).toBe("INFO");
  });
  it("local emulator defaults are a fact that says we could not tell, not a critical (corpus-h)", () => {
    const dev = "NEXT_PUBLIC_API_URL=http://localhost:8102\nEXAMPLE_SERVER_SECRET=Kq7Lm2Xz8Rt4Bn6Vc1Wd5Fh3Jp9Yt6Ue0Io4Pa8Sd2Fg\nEXAMPLE_SVIX_API_KEY=Wd5Fh3Jp9Yt6Ue0Io4Pa8Sd2FgKq7Lm2\n";
    expect(sev("apps/backend/.env.development", dev)).toBe("INFO");
    expect(sev("apps/backend/.env", dev)).toBe("INFO");
    expect(find("apps/backend/.env", dev)?.consequence).toMatch(/could not tell whether/);
  });
  it("a live credential under a test path is a warning that says so, not a placeholder note", () => {
    const f = find("examples/app/.env", "DATABASE_URL=postgresql://app:Zq8vLm2Rt5Xw@db.prod.example-host.com/app\n");
    expect(f?.severity).toBe("WARNING");
    expect(f?.consequence).not.toMatch(/placeholders or public by design/);
  });
  it("the fact wording says nothing private is exposed and no dashes", () => {
    const f = find(".env", "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\n");
    expect(f?.severity).toBe("INFO");
    expect(f?.consequence).toMatch(/nothing private is exposed/);
    for (const x of [f, find(".env", "EXAMPLE_SERVER_SECRET=Kq7Lm2Xz8Rt4Bn6Vc1Wd5Fh3Jp9\nAPI=http://localhost:1\n")]) {
      expect(x?.consequence).not.toMatch(/[\u2013\u2014]| - /);
    }
  });
});
