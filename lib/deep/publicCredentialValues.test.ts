import { describe, expect, it } from "vitest";
import { scanPublicCredentialValues } from "./clientExposure";

// Synthetic syntax fixtures only; none of these values authenticate anywhere.
const suffix = "9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5Hp0Ys2Jk";
const jwt = (role: string): string => {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "HS256", typ: "JWT" })}.${encode({ role, iss: "supabase" })}.c2ln`;
};

describe("public credential values — retained terminal evidence", () => {
  it.each([
    ["Stripe live", `sk_live_${suffix}`],
    ["Stripe test", `sk_test_${suffix}`],
    ["Anthropic", `sk-ant-${suffix}`],
    ["GitHub", `ghp_${suffix}`],
    ["Supabase", `sb_secret_${suffix}`],
    ["AWS", "AK" + "IA8Q2M7Z4N9T3R6V5X"],
  ])("retains %s literal evidence under a neutral public variable name", (_provider, value) => {
    const findings = scanPublicCredentialValues([
      { path: "lib/runtime.ts", content: `export const NEXT_PUBLIC_VALUE = ${JSON.stringify(value)};` },
    ]);
    expect(findings.some((finding) => finding.id.includes("public_prefixed_secret_value:NEXT_PUBLIC_VALUE"))).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(value);
  });

  it("decodes a service-role JWT even when the variable claims to be an anon key", () => {
    const value = jwt("service_role");
    const findings = scanPublicCredentialValues([
      { path: "lib/runtime.ts", content: `export const NEXT_PUBLIC_SUPABASE_ANON_KEY = ${JSON.stringify(value)};` },
    ]);
    expect(findings.some((finding) => finding.id.includes("public_prefixed_service_jwt:NEXT_PUBLIC_SUPABASE_ANON_KEY"))).toBe(true);
    expect(JSON.stringify(findings)).not.toContain(value);
  });

  it("does not infer a leak from a sensitive env name or a client import chain", () => {
    expect(scanPublicCredentialValues([
      { path: "app/page.tsx", content: '"use client"; import { key } from "../lib/server"; export default function Page() { return null; }' },
      { path: "lib/server.ts", content: "export const key = process.env.SUPABASE_SERVICE_ROLE_KEY;" },
      { path: "lib/runtime.ts", content: "export const key = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;" },
    ])).toEqual([]);
  });

  it("does not treat a sensitive variable name plus a harmless literal as a credential", () => {
    expect(scanPublicCredentialValues([
      { path: "lib/runtime.ts", content: 'export const NEXT_PUBLIC_SECRET_LABEL = "internal";' },
    ])).toEqual([]);
  });

  it("does not report anon JWTs or publishable provider keys", () => {
    expect(scanPublicCredentialValues([
      { path: "lib/runtime.ts", content: `export const NEXT_PUBLIC_SUPABASE_ANON_KEY = ${JSON.stringify(jwt("anon"))};` },
      { path: "lib/stripe.ts", content: `export const NEXT_PUBLIC_STRIPE_KEY = "pk_live_${suffix}";` },
    ])).toEqual([]);
  });

  it("does not mistake an ordinary authenticated JWT for a privileged service-role key", () => {
    expect(scanPublicCredentialValues([
      { path: "lib/runtime.ts", content: `export const NEXT_PUBLIC_SESSION = ${JSON.stringify(jwt("authenticated"))};` },
    ])).toEqual([]);
  });

  it("does not turn documented placeholder credentials into a test finding", () => {
    expect(scanPublicCredentialValues([
      { path: "lib/runtime.test.ts", content: 'const NEXT_PUBLIC_VALUE = "ghp_example_placeholder_value";' },
    ])).toEqual([]);
  });
});
