import { describe, expect, it } from "vitest";
import {
  jwtRole,
  resolveImport,
  scanClientExposure,
  scanPublicPrefixedSecrets,
  scanServerSecretsInClientCode,
  stripComments,
} from "./clientExposure";
import type { RepoFile } from "./githubScan";

const file = (path: string, content: string): RepoFile => ({ path, content });

// A legacy Supabase JWT is `header.payload.signature`, base64url, unsigned here
// (we only ever decode the payload — we never verify these).
const jwt = (role: string) => {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.c2ln`;
};

describe("stripComments — documentation must never be a finding", () => {
  it("removes line comments", () => {
    expect(stripComments("const a = 1; // SUPABASE_SERVICE_ROLE_KEY")).not.toContain("SERVICE_ROLE");
  });

  it("removes block comments, including multi-line ones", () => {
    expect(stripComments("/*\n * never use SERVICE_ROLE_KEY here\n */\nconst a = 1;")).not.toContain("SERVICE_ROLE");
  });

  it("keeps the code that surrounds a comment", () => {
    expect(stripComments("const a = 1; // note\nconst b = 2;")).toContain("const b = 2");
  });

  it("does not eat the // in a URL string literal", () => {
    expect(stripComments('fetch("https://api.example.com/x");')).toContain("api.example.com");
  });
});

describe("C10 — server-only secrets reachable from browser code", () => {
  it("flags a client component that reads the service-role key directly", () => {
    const out = scanServerSecretsInClientCode([
      file("app/admin/page.tsx", `"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain("bypasses RLS");
  });

  it("accepts a single-quoted use client directive", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `'use client'\nconst k = process.env.STRIPE_SECRET_KEY;`),
    ]);
    expect(out).toHaveLength(1);
  });

  it("stays silent on a SERVER component that reads the same key", () => {
    // No "use client" — this is the correct, intended way to use the key.
    expect(
      scanServerSecretsInClientCode([
        file("app/api/x/route.ts", `const k = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
      ])
    ).toEqual([]);
  });

  it("stays silent on a client component using the anon key", () => {
    expect(
      scanServerSecretsInClientCode([
        file("a.tsx", `"use client";\ncreateClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);`),
      ])
    ).toEqual([]);
  });

  it("does not fire on a comment warning against the key", () => {
    expect(
      scanServerSecretsInClientCode([
        file("a.tsx", `"use client";\n// never import SUPABASE_SERVICE_ROLE_KEY into a client component\nexport const A = 1;`),
      ])
    ).toEqual([]);
  });

  // The case that survives code review: the client file itself is clean.
  it("follows an import chain into a module that holds the secret", () => {
    const out = scanServerSecretsInClientCode([
      file("components/Table.tsx", `"use client";\nimport { fmt } from "@/lib/db";\nexport const T = () => fmt();`),
      file("lib/db.ts", `import { createClient } from "@supabase/supabase-js";\nexport const admin = createClient(u, process.env.SUPABASE_SERVICE_ROLE_KEY!);\nexport const fmt = () => 1;`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("through an import");
    expect(out[0].consequence).toContain("lib/db.ts");
  });

  it("names the full chain when the secret is two hops away", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `"use client";\nimport { b } from "./b";\nexport const A = b;`),
      file("b.ts", `export { c as b } from "./c";`),
      file("c.ts", `export const c = getSupabaseAdmin();`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].consequence).toContain("b.ts → c.ts");
  });

  it("resolves relative imports that climb directories", () => {
    const out = scanServerSecretsInClientCode([
      file("app/(d)/dashboard/Panel.tsx", `"use client";\nimport { q } from "../../../lib/admin";`),
      file("lib/admin.ts", `export const q = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
    ]);
    expect(out).toHaveLength(1);
  });

  it("resolves a directory import to its index file", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `"use client";\nimport { x } from "@/lib/server";`),
      file("lib/server/index.ts", `export const x = process.env.ENCRYPTION_KEY;`),
    ]);
    expect(out).toHaveLength(1);
  });

  it("ignores bare package imports rather than trying to resolve them", () => {
    expect(
      scanServerSecretsInClientCode([file("a.tsx", `"use client";\nimport React from "react";`)])
    ).toEqual([]);
  });

  it("terminates on a circular import instead of hanging", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `"use client";\nimport { b } from "./b";`),
      file("b.ts", `import { a } from "./a";\nexport const b = a;`),
    ]);
    expect(out).toEqual([]);
  });

  it("reports one finding per client component, not one per hop", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `"use client";\nimport { x } from "./s";\nimport { y } from "./t";`),
      file("s.ts", `export const x = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
      file("t.ts", `export const y = process.env.STRIPE_SECRET_KEY;`),
    ]);
    expect(out).toHaveLength(1);
  });

  it("flags each affected client component separately (each needs its own fix)", () => {
    const out = scanServerSecretsInClientCode([
      file("a.tsx", `"use client";\nimport { x } from "./s";`),
      file("b.tsx", `"use client";\nimport { x } from "./s";`),
      file("s.ts", `export const x = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
    ]);
    expect(out).toHaveLength(2);
    expect(new Set(out.map((finding) => finding.id)).size).toBe(2);
  });

  it("ignores non-code files entirely", () => {
    expect(
      scanServerSecretsInClientCode([file("README.md", `"use client" and SUPABASE_SERVICE_ROLE_KEY`)])
    ).toEqual([]);
  });

  it("does not treat a 'use client' string deep in a file as a directive", () => {
    const filler = "x".repeat(600);
    expect(
      scanServerSecretsInClientCode([
        file("a.ts", `${filler}\nconst doc = "use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
      ])
    ).toEqual([]);
  });

  it("survives an import of a file that isn't in the fetched file set", () => {
    expect(
      scanServerSecretsInClientCode([file("a.tsx", `"use client";\nimport { x } from "@/lib/missing";`)])
    ).toEqual([]);
  });

  it("handles an empty file list", () => {
    expect(scanServerSecretsInClientCode([])).toEqual([]);
  });
});

describe("resolveImport", () => {
  const byPath = new Map<string, RepoFile>([
    ["lib/a.ts", file("lib/a.ts", "")],
    ["src/lib/b.ts", file("src/lib/b.ts", "")],
    ["lib/c/index.tsx", file("lib/c/index.tsx", "")],
  ]);

  it("resolves an @/ alias", () => {
    expect(resolveImport("app/p.tsx", "@/lib/a", byPath)).toBe("lib/a.ts");
  });

  it("falls back to a src/ prefix when the project uses one", () => {
    expect(resolveImport("app/p.tsx", "@/lib/b", byPath)).toBe("src/lib/b.ts");
  });

  it("resolves a directory to its index", () => {
    expect(resolveImport("app/p.tsx", "@/lib/c", byPath)).toBe("lib/c/index.tsx");
  });

  it("resolves a relative path with .. segments", () => {
    expect(resolveImport("app/x/y/p.tsx", "../../../lib/a", byPath)).toBe("lib/a.ts");
  });

  it("returns null for a bare package specifier", () => {
    expect(resolveImport("app/p.tsx", "@supabase/supabase-js", byPath)).toBeNull();
    expect(resolveImport("app/p.tsx", "react", byPath)).toBeNull();
  });

  it("returns null for a local path that isn't in the file set", () => {
    expect(resolveImport("app/p.tsx", "./nope", byPath)).toBeNull();
  });
});

describe("jwtRole", () => {
  it("decodes the anon role", () => {
    expect(jwtRole(jwt("anon"))).toBe("anon");
  });

  it("decodes the service_role role", () => {
    expect(jwtRole(jwt("service_role"))).toBe("service_role");
  });

  it("returns null for a non-JWT string", () => {
    expect(jwtRole("sb_publishable_abc123")).toBeNull();
  });

  it("returns null for a JWT-shaped string with an undecodable payload", () => {
    expect(jwtRole("eyJhbGciOi.eyJub3RqLXNvbg.sig")).toBeNull();
  });

  it("returns null when the payload has no role claim", () => {
    expect(jwtRole(jwt(undefined as unknown as string))).toBeNull();
  });
});

describe("C11 — secrets behind a client-visible prefix", () => {
  it("flags a real secret value behind NEXT_PUBLIC_ as critical", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env.local", `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Habcdefghijklmnop`),
    ]);
    expect(out.some((finding) => finding.severity === "CRITICAL")).toBe(true);
  });

  it("flags a server-only NAME even with no visible value (a process.env read)", () => {
    const out = scanPublicPrefixedSecrets([
      file("lib/x.ts", `const k = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY;`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  // The anon and service-role keys look identical in the dashboard. This is the
  // whole reason the check decodes the payload instead of trusting the name.
  it("flags an ANON_KEY variable that actually holds the service_role JWT", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env", `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt("service_role")}`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("service_role");
    expect(out[0].severity).toBe("CRITICAL");
  });

  it("flags an ANON_KEY variable holding an sb_secret_ key", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env", `NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_secret_abcdefghijklmno`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("Supabase secret key");
  });

  it("stays SILENT on the correct anon key — the normal setup must not alert", () => {
    expect(
      scanPublicPrefixedSecrets([file(".env", `NEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt("anon")}`)])
    ).toEqual([]);
  });

  it("stays silent on the other legitimately-public variables", () => {
    expect(
      scanPublicPrefixedSecrets([
        file(
          ".env",
          [
            "NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co",
            "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=sb_publishable_abc123",
            "NEXT_PUBLIC_POSTHOG_KEY=phc_abc123",
            "NEXT_PUBLIC_APP_URL=https://example.com",
            "NEXT_PUBLIC_SENTRY_DSN=https://k@o1.ingest.sentry.io/1",
            "NEXT_PUBLIC_GOOGLE_CLIENT_ID=123-abc.apps.googleusercontent.com",
          ].join("\n")
        ),
      ])
    ).toEqual([]);
  });

  it("does not flag a server-only variable that has no public prefix", () => {
    expect(
      scanPublicPrefixedSecrets([file(".env", `SUPABASE_SERVICE_ROLE_KEY=${jwt("service_role")}`)])
    ).toEqual([]);
  });

  // .env.example placeholders are a naming problem, not a breach. Calling them
  // CRITICAL is how a scanner loses credibility.
  it("downgrades a placeholder value to a warning about the name", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env.example", `NEXT_PUBLIC_STRIPE_SECRET_KEY=your-secret-here`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("nothing has leaked yet");
  });

  it("treats an empty value as a placeholder", () => {
    const out = scanPublicPrefixedSecrets([file(".env.example", `NEXT_PUBLIC_API_SECRET=`)]);
    expect(out[0].severity).toBe("WARNING");
  });

  it("treats <angle-bracket> and ${...} templates as placeholders", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env.example", `NEXT_PUBLIC_A_SECRET=<your-key>\nNEXT_PUBLIC_B_SECRET=\${KEY}`),
    ]);
    expect(out).toHaveLength(2);
    expect(out.every((finding) => finding.severity === "WARNING")).toBe(true);
  });

  it("does not treat a forwarded env var as a hardcoded secret value", () => {
    const out = scanPublicPrefixedSecrets([
      file("next.config.ts", `export default { env: { NEXT_PUBLIC_X: process.env.REAL_KEY } };`),
    ]);
    expect(out).toEqual([]);
  });

  it("covers the other frameworks' public prefixes", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env", `VITE_STRIPE_SECRET_KEY=sk_live_51Habcdefghijk\nREACT_APP_DB_PASSWORD=hunter2hunter2`),
    ]);
    expect(out.length).toBeGreaterThanOrEqual(2);
  });

  it("ignores a public-prefixed secret mentioned only in a comment", () => {
    expect(
      scanPublicPrefixedSecrets([
        file("lib/x.ts", `// do not add NEXT_PUBLIC_SERVICE_ROLE_KEY\nexport const a = 1;`),
      ])
    ).toEqual([]);
  });

  it("does not scan prose files like the README", () => {
    expect(
      scanPublicPrefixedSecrets([file("README.md", `Set NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Habcdefg`)])
    ).toEqual([]);
  });

  it("dedupes the same variable in the same file", () => {
    const out = scanPublicPrefixedSecrets([
      file("lib/x.ts", `process.env.NEXT_PUBLIC_APP_SECRET;\nprocess.env.NEXT_PUBLIC_APP_SECRET;`),
    ]);
    expect(out).toHaveLength(1);
  });

  it("reports the same variable in two different files separately", () => {
    const out = scanPublicPrefixedSecrets([
      file("lib/a.ts", `process.env.NEXT_PUBLIC_APP_SECRET;`),
      file("lib/b.ts", `process.env.NEXT_PUBLIC_APP_SECRET;`),
    ]);
    expect(out).toHaveLength(2);
  });

  // One variable is one problem. A name that looks server-only AND a value that
  // IS a secret is still a single fix, and the value finding is the better of
  // the two because it names the actual key type.
  it("reports a secret-named variable holding a real secret value ONCE, by value", () => {
    const out = scanPublicPrefixedSecrets([
      file(".env.local", `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Habcdefghijklmnop`),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toContain("public_prefixed_secret_value");
    expect(out[0].title).toContain("live Stripe secret key");
  });

  it("still reports by name when the value is present but not a recognised secret shape", () => {
    const out = scanPublicPrefixedSecrets([file(".env.local", `NEXT_PUBLIC_APP_SECRET=zK92hfjeQ1x8`)]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toContain("public_prefixed_secret:");
    expect(out[0].severity).toBe("CRITICAL");
  });

  it("handles an empty file list", () => {
    expect(scanPublicPrefixedSecrets([])).toEqual([]);
  });
});

describe("scanClientExposure — aggregate", () => {
  it("returns both checks' findings with distinct, stable ids", () => {
    const out = scanClientExposure([
      file("a.tsx", `"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
      file(".env", `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Habcdefghijk`),
    ]);
    expect(out.length).toBe(2);
    expect(new Set(out.map((finding) => finding.id)).size).toBe(2);
    expect(out.every((finding) => finding.id.startsWith("github:"))).toBe(true);
  });

  it("is silent on a correctly-built app", () => {
    expect(
      scanClientExposure([
        file(".env", `NEXT_PUBLIC_SUPABASE_URL=https://a.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${jwt("anon")}\nSUPABASE_SERVICE_ROLE_KEY=${jwt("service_role")}`),
        file("app/api/x/route.ts", `import { getSupabaseAdmin } from "@/lib/supabase";\nexport async function GET() { getSupabaseAdmin(); return new Response("ok"); }`),
        file("lib/supabase.ts", `export const getSupabaseAdmin = () => createClient(u, process.env.SUPABASE_SERVICE_ROLE_KEY!);`),
        file("components/Form.tsx", `"use client";\nimport { supabaseBrowser } from "@/lib/supabaseBrowser";\nexport const F = () => null;`),
        file("lib/supabaseBrowser.ts", `export const supabaseBrowser = () => createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);`),
      ])
    ).toEqual([]);
  });

  it("returns findings that satisfy the shared GithubFinding shape", () => {
    const out = scanClientExposure([
      file("a.tsx", `"use client";\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;`),
    ]);
    for (const finding of out) {
      expect(finding.packageName).toBeNull();
      expect(finding.version).toBeNull();
      expect(finding.vulnId).toBeNull();
      expect(finding.cveId).toBeNull();
      expect(finding.title.length).toBeGreaterThan(0);
      expect(finding.consequence.length).toBeGreaterThan(0);
    }
  });
});
