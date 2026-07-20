import { describe, expect, it } from "vitest";
import { buildMigrationFix, buildCodeFix, buildDeepLink, extractSql, slug } from "./content";
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
