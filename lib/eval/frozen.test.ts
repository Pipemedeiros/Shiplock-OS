import { describe, expect, it } from "vitest";
import { deterministicFindings } from "@/lib/agent/deterministicFindings";
import { scoreBenchmark, type BenchFinding, type BenchLabel } from "./benchmark";

// Plan item H: a frozen, labeled fixture set in the normal test run, so a
// precision regression in what a founder sees fails the build. Each case is a
// shape read by hand in the 2026-10-06 census or on CORPUS-5 (values are
// synthetic). Only shapes fixed today are here; the known open false shapes
// are listed in the withheld labels-corpus5-deterministic-2026-10-06
// and join this set when fixed.
type Case = { name: string; real: boolean; files: { path: string; content: string }[] };
const LIVE_DB = ["postgresql://app:", "Zq8vLm2Rt5Xw", "@ep-gentle-scene-pooler.us-east-2.aws.neon.tech/neondb"].join("");

const cases: Case[] = [
  // Real: each must set the status.
  { name: "hosted database URL with a password in a committed .env.save (corpus-f)", real: true,
    files: [{ path: ".env.save", content: `DATABASE_URL=${LIVE_DB}\n` }] },
  { name: "a secret mapped into next.config env (corpus-i)", real: true,
    files: [{ path: "next.config.js", content: "module.exports = { env: { NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET } };\n" }] },
  { name: "a sign-in code from Math.random (corpus-j)", real: true,
    files: [{ path: "lib/auth.ts", content: "export const otp = Math.floor(100000 + Math.random() * 900000);\n" }] },
  { name: "browser code sends an API key to the app's own endpoint in the query (corpus-k)", real: true,
    files: [{ path: "src/components/Panel.tsx", content: "await fetch(`/api/indexing/bing?siteUrl=${u}&apiKey=${encodeURIComponent(key)}`);\n" }] },
  // False: none may set the status.
  { name: "a generator template's SQLite path (corpus-ae)", real: false,
    files: [{ path: "packages/generator/templates/app/.env.local", content: 'DATABASE_URL="file:./db/db.db"\n' }] },
  { name: "a public client id and URL in next.config env (corpus-i)", real: false,
    files: [{ path: "next.config.js", content: "module.exports = { env: { GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID, NEXTAUTH_URL: process.env.NEXTAUTH_URL } };\n" }] },
  { name: "a provider that requires the token in the query (Meta Graph)", real: false,
    files: [{ path: "utils/fb.ts", content: "await fetch(`https://graph.facebook.com/${v}/${id}/events?access_token=${accessToken}`);\n" }] },
  { name: "Stripe's checkout session_id and a job sessionId", real: false,
    files: [{ path: "app/confirm/page.tsx", content: "fetch(`/api/ads/confirm?session_id=${encodeURIComponent(sessionId)}`);\nfetch(`/api/enrich?sessionId=${s}`);\n" }] },
  { name: "a localhost test script", real: false,
    files: [{ path: "cron-tester.ts", content: "await fetch(`http://localhost:3000/api${endpoint}?apiKey=${apiKey}`);\n" }] },
  // CORPUS-5 false shapes, fixed 2026-10-06 (development; measured on CORPUS-6).
  { name: "a provider token on a continuation line of a multi-line URL (corpus-aj)", real: false,
    files: [{ path: "lib/threads.ts", content: "const r = await fetch(\n  `https://graph.threads.net/v1.0/me?fields=id,username` +\n  `&access_token=${token}`\n);\n" }] },
  { name: "a public analytics id in next.config env (corpus-l)", real: false,
    files: [{ path: "next.config.js", content: "module.exports = { env: { GA_ID: process.env.GA_ID } };\n" }] },
  { name: "bracketed placeholders in a committed .env.production (triumph)", real: false,
    files: [{ path: ".env.production", content: "SUPABASE_DB_URL=postgresql://postgres:[password]@aws-0-[region].pooler.supabase.com:6543/postgres\nSUPABASE_SERVICE_ROLE_KEY=your-service-role-key\n" }] },
  { name: "a test env file named .env.tests (corpus-m)", real: false,
    files: [{ path: "app/.env.tests", content: "NEXT_AUTH_SECRET=secret123secret\nAPI_KEY=testkey\n" }] },
  // CORPUS-6 shapes, fixed 2026-10-06 (development; measured on the next held-out set).
  { name: "a password reset token and OTP from Math.random (corpus-ak)", real: true,
    files: [{ path: "app/actions/auth-actions.ts", content: "const resetToken = Math.random().toString(36).substring(2, 15);\n" }] },
  { name: "a template's placeholder database host in a committed env (corpus-n)", real: false,
    files: [{ path: "project/config/.env.required", content: "DATABASE_URL=postgresql://postgres:Zq8vLm2Rt5Xw@db.your-project.supabase.co:5432/postgres\n" }] },
  { name: "local development values a committed env file could not settle (corpus-o)", real: false,
    files: [{ path: ".env.development", content: "DATABASE_URL=postgresql://postgres@localhost:5432/app\nTEST_AUTH_TOKEN=Kq7Lm2Xz8Rt4Bn6Vc1Wd5Fh3Jp9Yt6Ue0Io4Pa8\n" }] },
  { name: "a count of LLM tokens from Math.random (corpus-p)", real: false,
    files: [{ path: "app/workflows/page.tsx", content: "const tokens = data.tokens ?? Math.floor(Math.random() * 800 + 200);\n" }] },
  { name: "a chat session id from Math.random (corpus-al)", real: false,
    files: [{ path: "lib/client.ts", content: "this.sessionId = `corpus-r21-${Date.now()}-${Math.random().toString(36).slice(2)}`;\n" }] },
  { name: "an outside provider behind an unresolved base (corpus-q)", real: false,
    files: [{ path: "server/oauth.ts", content: "await fetch(`${IFLOW_CONFIG.userInfoUrl}?accessToken=${encodeURIComponent(token)}`);\n" }] },
  { name: "a placeholder API key in a code sample (corpus-r)", real: false,
    files: [{ path: "patterns/prisma.ts", content: 'const sample = `DATABASE_URL="prisma://accelerate.prisma-data.net/?api_key=YOUR_API_KEY"`;\n' }] },
  { name: "the Supabase anon key in next.config env (corpus-s)", real: false,
    files: [{ path: "next.config.js", content: "module.exports = { env: { SUPABASE_ANON_KEY: process.env.SUPABASE_ANON_KEY } };\n" }] },
  { name: "an encryption secret in next.config env (corpus-s)", real: true,
    files: [{ path: "next.config.js", content: "module.exports = { env: { CRYPTOJS_SECRET_KEY: process.env.CRYPTOJS_SECRET_KEY } };\n" }] },
  { name: "a committed env file holding only public values (Supabase anon)", real: false,
    files: [{ path: ".env", content: "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\n" }] },
];

describe("frozen precision fixtures (plan item H)", () => {
  const findings: BenchFinding[] = [];
  const labels: BenchLabel[] = [];
  for (const c of cases) {
    for (const f of deterministicFindings(c.files)) {
      findings.push({ repo: c.name, id: f.id, severity: f.severity as BenchFinding["severity"], attackClass: "deterministic" });
      const verdict = c.real ? { accurate: "yes", real: "yes" } as const : { accurate: "no", real: "no" } as const;
      labels.push({ repo: c.name, id: f.id, labelers: [verdict, verdict] });
    }
  }
  const report = scoreBenchmark(findings, labels, { observedPrecisionAtLeast: 0.9, lowerBound95AtLeast: 0, minimumLabeledFindings: 0, repositoriesWithCorrectStatusAtLeast: 0.9 });

  it.each(cases.filter((c) => c.real))("still sets the status: $name", (c) => {
    expect(report.repositories.find((r) => r.repo === c.name)?.status).not.toBe("no_open_issues");
  });

  it.each(cases.filter((c) => !c.real))("no longer sets the status: $name", (c) => {
    expect(report.repositories.find((r) => r.repo === c.name)?.status ?? "no_open_issues").toBe("no_open_issues");
  });

  it("is at 100% precision and status correctness on the frozen set", () => {
    expect(report.statusSetting.precision).toBe(1);
    expect(report.statusCorrect.share).toBe(1);
  });
});
