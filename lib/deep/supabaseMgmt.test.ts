import { describe, it, expect } from "vitest";
import { assertReadOnly } from "./supabaseMgmt";

// The guard that keeps CLAUDE.md's non-negotiable true: ShipLock never writes a
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
