import { describe, expect, it } from "vitest";
import {
  assertConnectableHost,
  assertReadOnlyRole,
  parseConnectionString,
  PostgresConnectionError,
} from "./postgresDirect";
import type { HostResolver } from "@/lib/security/ssrfGuard";

const resolveTo = (...addresses: string[]): HostResolver => ({
  lookup: async () => addresses,
});

describe("parseConnectionString", () => {
  it("accepts a normal connection string and reports its parts", () => {
    const c = parseConnectionString("postgres://reader:pw@db.example.com:6543/appdb");
    expect(c.host).toBe("db.example.com");
    expect(c.port).toBe(6543);
    expect(c.database).toBe("appdb");
    expect(c.user).toBe("reader");
  });

  it("defaults the port to 5432", () => {
    expect(parseConnectionString("postgresql://u:p@db.example.com/appdb").port).toBe(5432);
  });

  it("forces TLS on, even when the customer explicitly disabled it", () => {
    // The failure this prevents is ours, not theirs: a founder pastes a DSN from
    // a local setup, and on OUR instruction their database password crosses the
    // public internet in the clear. Upgrading silently is the right call because
    // there is no legitimate reason for us to connect without TLS.
    const c = parseConnectionString("postgres://u:p@db.example.com/appdb?sslmode=disable");
    expect(c.dsn).toContain("sslmode=require");
    expect(c.dsn).not.toContain("sslmode=disable");
  });

  it.each([
    ["", "empty"],
    ["not a url", "garbage"],
    ["mysql://u:p@db.example.com/appdb", "wrong scheme"],
    ["https://db.example.com/appdb", "http scheme"],
    ["postgres://db.example.com/appdb", "no user"],
    ["postgres://u:p@db.example.com", "no database"],
  ])("rejects %s (%s)", (dsn) => {
    expect(() => parseConnectionString(dsn)).toThrow(PostgresConnectionError);
  });

  it("rejects an absurdly long string before parsing it", () => {
    expect(() => parseConnectionString(`postgres://u:p@h/${"x".repeat(4000)}`)).toThrow(
      PostgresConnectionError
    );
  });
});

describe("assertConnectableHost", () => {
  it("allows a public address", async () => {
    await expect(assertConnectableHost("db.example.com", resolveTo("52.1.2.3"))).resolves.toBeUndefined();
  });

  it.each([
    ["127.0.0.1", "loopback"],
    ["10.0.0.5", "private"],
    ["169.254.169.254", "cloud metadata"],
    ["192.168.1.1", "LAN"],
  ])("refuses %s (%s)", async (ip) => {
    await expect(assertConnectableHost("evil.example.com", resolveTo(ip))).rejects.toMatchObject({
      code: "blocked_host",
    });
  });

  it("refuses a host that resolves to both a public and a private address", async () => {
    // DNS rebinding: checking only the first answer would pass this and then
    // connect to the private one. A connection string is the most literal SSRF
    // primitive we accept, so every answer has to be public.
    await expect(
      assertConnectableHost("rebind.example.com", resolveTo("52.1.2.3", "10.0.0.5"))
    ).rejects.toMatchObject({ code: "blocked_host" });
  });

  it("reports an unresolvable host as unreachable, not blocked", async () => {
    await expect(
      assertConnectableHost("nope.example.com", { lookup: async () => [] })
    ).rejects.toMatchObject({ code: "unreachable" });
  });
});

describe("assertReadOnlyRole", () => {
  const rolesRow = (over: Partial<{ rolsuper: boolean; rolbypassrls: boolean }> = {}) => ({
    rolsuper: false,
    rolbypassrls: false,
    ...over,
  });

  const queryReturning = (role: object, writableCount: string) => {
    return async <R>(sql: string): Promise<R[]> => {
      if (sql.includes("pg_roles")) return [role] as R[];
      return [{ count: writableCount }] as R[];
    };
  };

  it("accepts a role with no write grants", async () => {
    await expect(assertReadOnlyRole(queryReturning(rolesRow(), "0"))).resolves.toBeUndefined();
  });

  it("refuses a superuser", async () => {
    // A superuser bypasses RLS and every grant, so no amount of table-level
    // permission checking would catch it — it has to be its own assertion.
    await expect(
      assertReadOnlyRole(queryReturning(rolesRow({ rolsuper: true }), "0"))
    ).rejects.toMatchObject({ code: "not_read_only" });
  });

  it("refuses a role that can bypass RLS", async () => {
    // Especially important here: our entire database finding set is about what
    // RLS does or does not stop. A role that ignores RLS would read rows a real
    // user could not, and every policy would look permissive.
    await expect(
      assertReadOnlyRole(queryReturning(rolesRow({ rolbypassrls: true }), "0"))
    ).rejects.toMatchObject({ code: "not_read_only" });
  });

  it("refuses a role holding write grants", async () => {
    await expect(
      assertReadOnlyRole(queryReturning(rolesRow(), "3"))
    ).rejects.toMatchObject({ code: "not_read_only" });
  });
});

describe("error messages never leak the credential", () => {
  it("keeps the password out of parse failures", () => {
    try {
      parseConnectionString("postgres://user:hunter2@/nodb");
      throw new Error("should have thrown");
    } catch (err) {
      expect((err as Error).message).not.toContain("hunter2");
    }
  });
});
