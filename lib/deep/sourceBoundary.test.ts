import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { scanSecrets, type RepoFile } from "./githubScan";
import { scanPublicCredentialValues } from "./clientExposure";
import { scanCredentialHandling } from "./credentialHandling";
import { scanNextConfigEnv } from "./nextConfigEnv";
import { scanWorkflows } from "./workflowScan";

/**
 * The source-finding boundary, asserted in both directions.
 *
 * The rule this file enforces is the one recorded in docs/STATE.md under
 * "Why the pattern-check layer was deleted rather than narrowed": a check
 * belongs here only if the evidence in hand decides the claim it makes.
 *
 * The deletion it guards was measured, not guessed — 108 criticals and zero
 * true positives across fifteen repositories, none of which had been used to
 * find or fix anything beforehand. Without this file a future session can
 * reintroduce any of those checks and no test will notice, which is how the
 * layer grew the first time.
 *
 * If you are here because one of the "stays deleted" cases now fails, the
 * question to answer is not "can the pattern be tightened". It is: does the
 * evidence in the file decide the claim? For interpolated SQL, a bundled
 * import, a sink, or a name near a log line, it does not.
 */

const scan = (files: RepoFile[]) => [
  ...scanSecrets(files),
  ...scanPublicCredentialValues(files),
  ...scanCredentialHandling(files),
  ...scanNextConfigEnv(files),
  ...scanWorkflows(files),
];

const ids = (files: RepoFile[]) => scan(files).map((f) => f.id);

describe("checks that stay deleted — the shape does not decide the claim", () => {
  it.each([
    [
      "interpolated SQL in an execution call",
      "lib/q.ts",
      "const r = await conn.execute(`SELECT ${cols} FROM Link WHERE id = ${id}`);",
      /sql_injection/,
    ],
    [
      "a quoted SQL string containing a plus sign",
      "lib/health.ts",
      "await this.sqlClient.raw('SELECT 1+1 as data');",
      /sql_injection/,
    ],
    [
      "a shell command built by interpolation",
      "scripts/build.ts",
      "execSync(`git commit -m \"${message}\"`);",
      /command_injection/,
    ],
    [
      "an XSS sink with no traced source",
      "components/x.tsx",
      'export const A = () => <div dangerouslySetInnerHTML={{ __html: html }} />;',
      /xss_sink/,
    ],
    [
      "a method that happens to be named eval",
      "lib/cache.server.ts",
      "await redis.eval(ADD_SCRIPT, 1, key, value);",
      /xss_sink/,
    ],
    [
      "an enum member whose name ends in PASSWORD",
      "lib/mail.ts",
      "export enum MailType { RESET_PASSWORD = 'reset-password' }",
      /generic_secret_assignment/,
    ],
    [
      "an identifier near a log call",
      "lib/log.ts",
      "console.log(`token prefix ${tokenPrefix} length ${secret.length}`);",
      /logged_secret/,
    ],
    [
      "sha1 and bcrypt co-occurring in one file",
      "lib/crypto.ts",
      "import { hash } from 'bcrypt';\nexport const sum = (b) => createHash('sha1').update(b).digest();",
      /weak_hash/,
    ],
    [
      "the default supabase-js client",
      "lib/supa.ts",
      "import { createClient } from '@supabase/supabase-js';\nexport const c = createClient(u, k);",
      /token_storage/,
    ],
  ])("stays silent on %s", (_label, path, content, pattern) => {
    expect(ids([{ path, content }]).filter((id) => pattern.test(id))).toEqual([]);
  });

  it("stays silent on a client component whose imports reach a server-only env name", () => {
    // The walker's premise: Next.js writes only NEXT_PUBLIC_-prefixed variables
    // and explicit next.config env entries into the client define map, so
    // process.env.STRIPE_SECRET_KEY is undefined in a bundle and no value ships.
    const files: RepoFile[] = [
      { path: "components/panel.tsx", content: '"use client";\nimport { cn } from "@/lib/util";\nexport const P = () => <div className={cn("x")} />;' },
      { path: "lib/util.ts", content: "export const cn = (x: string) => x;\nexport const s = process.env.STRIPE_SECRET_KEY;" },
    ];
    expect(ids(files).filter((id) => /client_server_secret/.test(id))).toEqual([]);
  });

  it("stays silent on an outsider-writable expression in a workflow run block", () => {
    // 21 criticals, 20 false. Its structural siblings are asserted below.
    const wf: RepoFile = {
      path: ".github/workflows/greet.yml",
      content: 'on:\n  pull_request:\njobs:\n  j:\n    steps:\n      - run: echo "${{ github.event.pull_request.title }}"\n',
    };
    expect(ids([wf]).filter((id) => /script_injection/.test(id))).toEqual([]);
  });
});

describe("checks that must keep firing — the evidence decides the claim", () => {
  // Generated per-run rather than committed: a real parseable key is exactly
  // what scanSecrets exists to report, so checking one into this repository
  // would be the finding.
  const rsa = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  }).privateKey as string;

  it("reports a committed private key that actually parses", () => {
    expect(ids([{ path: "config/key.pem", content: rsa }])).toContain("github:secret:private_key:config/key.pem");
  });

  it("does not strip a base64 line beginning with // as a comment", () => {
    // Generate test-only material, then wrap at a base64 // sequence. No key
    // is persisted. The normal PEM parser accepts arbitrary line lengths.
    let body = "";
    for (let attempt = 0; attempt < 256 && !body.includes("//"); attempt++) {
      const key = generateKeyPairSync("rsa", {
        modulusLength: 512,
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
      }).privateKey;
      body = key.replace(/-----[^\n]+-----/g, "").replace(/\s/g, "");
    }
    expect(body).toContain("//");
    const wrapped = body.replace("//", "\n//");
    const pem = `-----BEGIN PRIVATE KEY-----\n${wrapped}\n-----END PRIVATE KEY-----`;
    expect(ids([{ path: "config/key.pem", content: pem }])).toContain("github:secret:private_key:config/key.pem");
  });

  it("does not report a PEM header with no usable key body", () => {
    // corpus-ag's helm values.yaml carried a commented-out example header and was
    // reported CRITICAL before the parse guard.
    const fake = "##   -----BEGIN RSA PRIVATE KEY-----\n##   <your key here>\n";
    expect(ids([{ path: "deploy/values.yaml", content: fake }]).filter((i) => /private_key/.test(i))).toEqual([]);
  });

  it("reports an AWS access key id", () => {
    expect(ids([{ path: "lib/aws.ts", content: 'const a = "AKIA8Q2M7Z4N9T3R6V5X";' }]))
      .toContain("github:secret:aws_access_key:lib/aws.ts");
  });

  it("reports a next.config env block holding a literal credential", () => {
    const cfg: RepoFile = {
      path: "next.config.js",
      content: 'module.exports = { env: { PAY: "sk_live_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5" } };',
    };
    expect(ids([cfg]).some((i) => i.startsWith("github:next_config_env_credential:"))).toBe(true);
  });

  it("reports pull_request_target checking out the pull request head", () => {
    const wf: RepoFile = {
      path: ".github/workflows/label.yml",
      content:
        "on:\n  pull_request_target:\njobs:\n  j:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
    };
    expect(ids([wf])).toContain("github:workflow_prtarget_rce:.github/workflows/label.yml");
  });

  it("reports a third-party action pinned to a moveable tag", () => {
    const wf: RepoFile = {
      path: ".github/workflows/ci.yml",
      content: "on:\n  push:\njobs:\n  j:\n    permissions:\n      contents: read\n    steps:\n      - uses: pnpm/action-setup@v2\n",
    };
    expect(ids([wf])).toContain("github:workflow_unpinned_action:.github/workflows/ci.yml");
  });

  it("does not flag a local composite action or a first-party action as unpinned", () => {
    // twenty uses 75 local composite actions; counting those was a measurement
    // error on 2026-09-07 before the parsed count corrected it.
    const wf: RepoFile = {
      path: ".github/workflows/local.yml",
      content:
        "on:\n  push:\njobs:\n  j:\n    permissions:\n      contents: read\n    steps:\n      - uses: ./.github/actions/setup\n      - uses: actions/checkout@v4\n",
    };
    expect(ids([wf]).filter((i) => /unpinned/.test(i))).toEqual([]);
  });
});

describe("restored 2026-09-07 — the file decides its own claim", () => {
  // Deleted as collateral when sourcePatterns.ts went, restored because they
  // pass the boundary: neither needs evidence from outside the file. Their
  // false positives were all test scaffolding, which the shared path
  // classifier handles. See docs/TASK-A-MEASUREMENT-2026-09-07.md.
  const sev = (files: RepoFile[], pattern: RegExp) =>
    scan(files).filter((x) => pattern.test(x.id)).map((x) => x.severity);

  it("reports a security token built from Math.random (corpus-af's shape)", () => {
    const file: RepoFile = {
      path: "components/apps/make/Setup.tsx",
      content: 'const apiKey = `cal_live_${Math.random().toString(36).substring(2)}`;',
    };
    expect(sev([file], /insecure_random/)).toEqual(["WARNING"]);
  });

  it("reports a secret carried in a URL query string (corpus-b's shape)", () => {
    const file: RepoFile = {
      path: "pages/api/links/index.ts",
      content: 'await fetch(`${process.env.NEXTAUTH_URL}/api/revalidate?secret=${process.env.REVALIDATE_TOKEN}&id=${id}`);',
    };
    expect(sev([file], /secret_in_url/)).toEqual(["WARNING"]);
  });

  it("speaks one step quieter under a test path, and never drops the finding", () => {
    // The whole reason these two came back: the false positives were a path
    // problem, not a taint problem. Quieter, never silent.
    const inTest: RepoFile = {
      path: "apps/web/modules/api/v2/lib/tests/utils.test.ts",
      content: 'const r = new Request("http://localhost/api/test?apikey=123&token=abc");',
    };
    expect(sev([inTest], /secret_in_url/)).toEqual(["INFO"]);
    const seed: RepoFile = {
      path: "scripts/seed.ts",
      content: 'const sessionId = `s_${Math.random().toString(36)}`;',
    };
    expect(sev([seed], /insecure_random/)).toEqual(["INFO"]);
  });

  it("stays silent on Math.random that feeds nothing security-shaped", () => {
    const file: RepoFile = { path: "lib/ui.ts", content: "const jitter = Math.random() * 100;\nconst key = Math.random();" };
    expect(sev([file], /insecure_random/)).toEqual([]);
  });

  it("stays silent on a brace-delimited template placeholder, which carries no value", () => {
    // Stripe substitutes {CHECKOUT_SESSION_ID} when it builds the redirect.
    // corpus-af and corpus-d both write it verbatim; both were false on 2026-09-07.
    const stripe: RepoFile = {
      path: "lib/billing.ts",
      content: 'const url = `${base}/api/stripe/portal?session_id={CHECKOUT_SESSION_ID}`;',
    };
    expect(sev([stripe], /secret_in_url/)).toEqual([]);
  });

  it("stays silent on an ordinary query string", () => {
    const file: RepoFile = { path: "lib/search.ts", content: 'await fetch(`/api/search?q=${term}&page=2`);' };
    expect(sev([file], /secret_in_url/)).toEqual([]);
  });
});
