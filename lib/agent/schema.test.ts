import { describe, expect, it } from "vitest";
import { extractTables } from "./schema";

describe("extractTables", () => {
  it("reads Drizzle table declarations", () => {
    const tables = extractTables([
      { path: "db/schema.ts", content: 'export const invoices = pgTable("invoices", { id: uuid() });' },
    ]);
    expect(tables).toEqual(["invoices"]);
  });

  it("reads Prisma models and converts them to their table name", () => {
    const tables = extractTables([
      { path: "prisma/schema.prisma", content: "model WorkspaceMember {\n  id String @id\n}" },
    ]);
    expect(tables).toEqual(["workspace_member"]);
  });

  it("reads SQL migrations, with or without if-not-exists and a schema prefix", () => {
    const tables = extractTables([
      { path: "migrations/001.sql", content: 'create table if not exists public."audit_runs" (id uuid);' },
    ]);
    expect(tables).toEqual(["audit_runs"]);
  });

  it("reads Supabase client access, which is often the only declaration there is", () => {
    const tables = extractTables([
      { path: "lib/data.ts", content: 'await supabase.from("profiles").select("*")' },
    ]);
    expect(tables).toEqual(["profiles"]);
  });

  it("does not carry regex state between files", () => {
    // Module-level /g regexes share lastIndex. Without a reset, every second
    // file silently contributes nothing -- half a schema, reported as whole.
    const tables = extractTables([
      { path: "a.ts", content: 'pgTable("one", {})' },
      { path: "b.ts", content: 'pgTable("two", {})' },
      { path: "c.ts", content: 'pgTable("three", {})' },
    ]);
    expect(tables).toEqual(["one", "three", "two"]);
  });

  it("ignores test files, which are full of one-letter fixture tables", () => {
    // The first dogfood run produced tables called a, b, t, one, two, three and
    // AS. An inventory containing invented tables is worse than a short one:
    // the agent cites them, and the guard cannot tell a real table it has never
    // seen from a fake one it has.
    const tables = extractTables([
      { path: "lib/graph/attackPaths.test.ts", content: 'supabase.from("a").select()' },
      { path: "test/fixtures/seed.sql", content: "create table t (id int);" },
      { path: "lib/data.ts", content: 'supabase.from("invoices").select()' },
    ]);
    expect(tables).toEqual(["invoices"]);
  });

  it("rejects SQL keywords a greedy match picks up as names", () => {
    const tables = extractTables([
      { path: "migrations/1.sql", content: "create table if not exists public.orders (id uuid);" },
    ]);
    expect(tables).toEqual(["orders"]);
  });

  it("returns nothing for an unrecognised schema, rather than inventing tables", () => {
    expect(extractTables([{ path: "app.rb", content: "class User < ActiveRecord::Base; end" }])).toEqual([]);
  });
});
