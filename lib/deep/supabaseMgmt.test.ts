import { describe, it, expect, vi } from "vitest";
import {
  assertReadOnly, buildRowCountSql, quoteIdent, fetchPolicies, fetchAdvisors,
  fetchAuthConfig, fetchBackupConfig, fetchAuthAuditLog,
} from "./supabaseMgmt";

// The guard that keeps AGENTS.md's non-negotiable true: ShipLock never writes a
// customer's production database. The Management API query endpoint would
// happily run a write, so anything that isn't a single read is refused before
// it leaves us.
describe("assertReadOnly", () => {
  it("allows a plain SELECT", () => {
    expect(() => assertReadOnly("SELECT * FROM pg_policies WHERE schemaname = 'public'")).not.toThrow();
  });

  it("allows a trailing semicolon", () => {
    expect(() => assertReadOnly("SELECT 1;")).not.toThrow();
  });

  it("allows a CTE that reads", () => {
    expect(() => assertReadOnly("WITH p AS (SELECT 1) SELECT * FROM p")).not.toThrow();
  });

  it.each([
    ["INSERT INTO users VALUES (1)"],
    ["UPDATE users SET admin = true"],
    ["DELETE FROM users"],
    ["DROP TABLE users"],
    ["TRUNCATE users"],
    ["ALTER TABLE users ENABLE ROW LEVEL SECURITY"],
    ["CREATE POLICY p ON users USING (true)"],
    ["GRANT ALL ON users TO anon"],
    ["REVOKE ALL ON users FROM anon"],
  ])("refuses %s", (sql) => {
    expect(() => assertReadOnly(sql)).toThrow();
  });

  // One semicolon is all it takes to append a write to an innocent read.
  it("refuses stacked statements", () => {
    expect(() => assertReadOnly("SELECT 1; DROP TABLE users")).toThrow(/multi-statement/i);
  });

  it("refuses a write hidden after a leading SELECT", () => {
    expect(() => assertReadOnly("SELECT * FROM t WHERE x = 1 UNION SELECT 1; UPDATE t SET a=1")).toThrow();
  });

  it("refuses an empty or non-statement", () => {
    expect(() => assertReadOnly("")).toThrow();
    expect(() => assertReadOnly("   ")).toThrow();
  });

  it("is case-insensitive", () => {
    expect(() => assertReadOnly("dRoP TaBlE users")).toThrow();
  });
});

describe("schema inventory SQL", () => {
  it("builds a single UNION ALL statement", () => {
    const sql = buildRowCountSql(["profiles", "payments"])!;
    expect(sql).toContain("union all");
    expect(sql.split(";").length).toBe(1);
  });

  // The transport's guarantee only holds if what we hand it is a single SELECT.
  it("passes its own read-only guard", () => {
    expect(() => assertReadOnly(buildRowCountSql(["profiles"])!)).not.toThrow();
  });

  it("refuses table names that are not plain identifiers", () => {
    expect(buildRowCountSql(['users"; drop table x; --'])).toBeNull();
    expect(buildRowCountSql(["a b"])).toBeNull();
  });

  it("keeps the valid tables when one is rejected", () => {
    const sql = buildRowCountSql(["profiles", "bad name"])!;
    expect(sql).toContain("profiles");
    expect(sql).not.toContain("bad name");
  });

  it("returns null for no usable tables", () => {
    expect(buildRowCountSql([])).toBeNull();
  });

  it("quotes identifiers", () => {
    expect(quoteIdent("profiles")).toBe('"profiles"');
  });
});

describe("caller cancellation reaches Management API requests", () => {
  it.each([
    ["fetchPolicies", (signal: AbortSignal) => fetchPolicies("token", "ref", signal)],
    ["fetchAdvisors", (signal: AbortSignal) => fetchAdvisors("token", "ref", signal)],
    ["fetchAuthConfig", (signal: AbortSignal) => fetchAuthConfig("token", "ref", signal)],
    ["fetchBackupConfig", (signal: AbortSignal) => fetchBackupConfig("token", "ref", signal)],
    ["fetchAuthAuditLog", (signal: AbortSignal) => fetchAuthAuditLog("token", "ref", signal)],
  ])("%s aborts its in-flight fetch when the collector signal aborts", async (_name, call) => {
    let seen: AbortSignal | undefined;
    const fetchMock = vi.fn((_url: unknown, init?: RequestInit) => {
      seen = init?.signal ?? undefined;
      return new Promise<Response>(() => {});
    });
    vi.stubGlobal("fetch", fetchMock);
    try {
      const caller = new AbortController();
      void call(caller.signal).catch(() => {});
      await Promise.resolve();
      expect(seen?.aborted).toBe(false);
      caller.abort(new Error("collector timed out"));
      expect(seen?.aborted).toBe(true);
    } finally { vi.unstubAllGlobals(); }
  });
});
