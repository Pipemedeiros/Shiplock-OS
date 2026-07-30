import { describe, expect, it } from "vitest";
import { buildMigrationFix, buildCodeFix, buildDeepLink, extractSql, repoFromFindingId, slug } from "./content";
import type { FixableFinding } from "./lane";

const NOW = new Date("2026-07-17T21:45:00Z");
const f = (over: Partial<FixableFinding>): FixableFinding => ({
  id: "x", source: "scan", title: "Table has no RLS", severity: "CRITICAL", fix: "", ...over,
});

describe("extractSql", () => {
  it("takes SQL after the 'SQL Editor:' marker", () => {
    expect(extractSql("Run in Supabase SQL Editor:\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;")).toBe(
      "ALTER TABLE orders ENABLE ROW LEVEL SECURITY;"
    );
  });
  it("keeps SQL-looking lines when there's no marker", () => {
    expect(extractSql("Do this:\nCREATE POLICY p ON t USING (auth.uid() = user_id);\nthanks")).toContain("CREATE POLICY");
  });
  it("returns null when there's no SQL", () => {
    expect(extractSql("Go to the dashboard and toggle the setting.")).toBeNull();
  });
});

describe("buildMigrationFix", () => {
  it("emits a migration file with the extracted SQL", () => {
    const a = buildMigrationFix(f({ fix: "Run in Supabase SQL Editor:\nALTER TABLE orders ENABLE ROW LEVEL SECURITY;" }), NOW);
    expect(a.path).toBe("supabase/migrations/20260717214500_shiplock_table-has-no-rls.sql");
    expect(a.content).toContain("ALTER TABLE orders ENABLE ROW LEVEL SECURITY;");
    expect(a.content).toContain("ShipLock never writes to your database directly");
  });
  it("scaffolds a TODO migration when no clean SQL is available", () => {
    const a = buildMigrationFix(f({ title: "Permissive policy", fix: "Scope it to the owner." }), NOW);
    expect(a.content).toContain("TODO: complete the SQL");
    expect(a.content).toContain("Guidance: Scope it to the owner.");
  });
});

describe("buildCodeFix", () => {
  it("emits a fix-request markdown with the change + file", () => {
    const a = buildCodeFix(f({ id: "github:injection:sql_injection:api/u.ts", source: "github", title: "SQL injection", fix: "Use parameterized queries.", filePath: "api/u.ts" }), NOW);
    expect(a.path).toBe("shiplock-fixes/20260717214500-sql-injection.md");
    expect(a.content).toContain("Use parameterized queries.");
    expect(a.content).toContain("`api/u.ts`");
    expect(a.content).toContain("never rewrites application logic automatically");
  });
});

describe("buildDeepLink", () => {
  it("routes leaked-password → auth providers", () => {
    expect(buildDeepLink(f({ title: "Leaked password protection disabled", fix: "enable it" }), "ref123")).toBe(
      "https://supabase.com/dashboard/project/ref123/auth/providers"
    );
  });
  it("routes a rotate instruction → api settings", () => {
    expect(buildDeepLink(f({ title: "Service role key", fix: "Rotate the service_role key." }), "ref123")).toContain("/settings/api");
  });
  it("falls back to the project picker (valid URL) when no project ref", () => {
    // Without a ref, a settings path would be malformed — send to the picker.
    expect(buildDeepLink(f({ title: "Leaked password", fix: "enable it" }))).toBe("https://supabase.com/dashboard/projects");
  });
});

describe("slug", () => {
  it("kebab-cases and trims", () => {
    expect(slug("Table has NO RLS!!")).toBe("table-has-no-rls");
  });
});

describe("buildDeepLink — honest destinations", () => {
  const f = (id: string, fix = "rotate the key", title = "t") => ({
    id,
    source: "github" as const,
    title,
    severity: "CRITICAL" as const,
    fix,
  });

  it("extracts owner/name from a namespaced finding id", () => {
    expect(repoFromFindingId("acme/app::github:repo_public:acme/app")).toBe("acme/app");
  });

  it("returns null for an id with no repo prefix", () => {
    expect(repoFromFindingId("email_auth:spf_missing")).toBeNull();
    expect(repoFromFindingId("bundle:shipped_secret:x")).toBeNull();
  });

  it("links repo visibility to that repo's settings page", () => {
    expect(buildDeepLink(f("acme/app::github:repo_public:acme/app"), "ref123", "github")).toBe(
      "https://github.com/acme/app/settings"
    );
  });

  it("falls back to the repo list when the id carries no repo", () => {
    expect(buildDeepLink(f("github:repo_public:x"), "ref123", "github")).toBe(
      "https://github.com/settings/repositories"
    );
  });

  // A confident link to the wrong page lets someone believe they did the fix.
  it("returns NO link for a DNS fix, because we don't know who runs their DNS", () => {
    expect(buildDeepLink(f("email_auth:spf_missing", "add a TXT record"), "ref123", "dns")).toBeNull();
  });

  it("returns NO link for a third-party key rotation", () => {
    expect(
      buildDeepLink(
        f("bundle:shipped_secret:stripe_live_secret", "Roll it in the Stripe dashboard", "Stripe key leaked"),
        "ref123",
        "provider"
      )
    ).toBeNull();
  });

  it("DOES link a Supabase key rotation to the API settings page", () => {
    expect(
      buildDeepLink(
        f("bundle:shipped_secret:supabase_secret_key", "Rotate it in Supabase Project Settings", "Supabase key"),
        "ref123",
        "provider"
      )
    ).toBe("https://supabase.com/dashboard/project/ref123/settings/api");
  });

  it("sends redirect allow-list and Site URL fixes to the URL configuration page", () => {
    expect(
      buildDeepLink(f("auth_redirect:wildcard_any_host", "remove the entry", "redirect allow-list"), "ref123", "supabase")
    ).toBe("https://supabase.com/dashboard/project/ref123/auth/url-configuration");
    expect(
      buildDeepLink(f("auth_site_url:localhost", "set it to production", "Your Site URL"), "ref123", "supabase")
    ).toBe("https://supabase.com/dashboard/project/ref123/auth/url-configuration");
  });

  it("still sends the user to the project picker with no project ref", () => {
    expect(buildDeepLink(f("advisor:jwt", "jwt"), null, "supabase")).toBe("https://supabase.com/dashboard/projects");
  });
});
