import { describe, expect, it } from "vitest";
import {
  checkCronJobs,
  checkExtensionSchemas,
  checkForeignServers,
  checkNetworkGrants,
  EXTENSION_SQL,
  NETWORK_GRANT_SQL,
  scanExtensions,
} from "./extensionScan";
import { assertReadOnly } from "./supabaseMgmt";

// The real baseline of a Supabase project, read from ours. A check that fires on
// this is worthless.
const SUPABASE_DEFAULT = [
  { name: "pg_stat_statements", schema: "extensions" },
  { name: "pgcrypto", schema: "extensions" },
  { name: "plpgsql", schema: "pg_catalog" },
  { name: "supabase_vault", schema: "vault" },
  { name: "uuid-ossp", schema: "extensions" },
];

describe("A8 — extension schema", () => {
  it("is SILENT on a default Supabase install", () => {
    expect(checkExtensionSchemas(SUPABASE_DEFAULT)).toEqual([]);
  });

  it("flags an extension in public", () => {
    const out = checkExtensionSchemas([...SUPABASE_DEFAULT, { name: "postgis", schema: "public" }]);
    expect(out).toHaveLength(1);
    expect(out[0].consequence).toContain("alter extension postgis set schema extensions");
  });

  it("names every offender in one finding", () => {
    const out = checkExtensionSchemas([
      { name: "postgis", schema: "public" },
      { name: "hstore", schema: "public" },
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("postgis, hstore");
  });
});

describe("A15 — outbound HTTP from a public role", () => {
  // pg_net installed is ordinary; Supabase uses it for webhooks.
  it("is silent when nothing is granted", () => {
    expect(checkNetworkGrants([])).toEqual([]);
  });

  it("flags execute granted to a browser-reachable role", () => {
    const out = checkNetworkGrants([{ schema: "net", name: "http_post", grantee: "anon" }]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  // The reason SSRF from a database is worse than SSRF from an app server.
  it("explains metadata endpoints and exfiltration", () => {
    const out = checkNetworkGrants([{ schema: "net", name: "http_get", grantee: "authenticated" }]);
    expect(out[0].consequence).toContain("cloud metadata endpoints");
    expect(out[0].consequence).toContain("exfiltration");
  });

  it("lists every role and function once", () => {
    const out = checkNetworkGrants([
      { schema: "net", name: "http_get", grantee: "anon" },
      { schema: "net", name: "http_get", grantee: "authenticated" },
      { schema: "net", name: "http_post", grantee: "anon" },
    ]);
    expect(out[0].consequence).toContain("anon and authenticated");
    expect(out[0].consequence).toContain("net.http_get, net.http_post");
  });
});

describe("A16 — scheduled jobs", () => {
  const job = (over: Partial<Parameters<typeof checkCronJobs>[0][0]> = {}) => ({
    name: "nightly", schedule: "0 3 * * *", runs_as: "app_user", command: "select 1", ...over,
  });

  it("is silent when there are no jobs", () => {
    expect(checkCronJobs([])).toEqual([]);
  });

  it("is silent on an ordinary job", () => {
    expect(checkCronJobs([job()])).toEqual([]);
  });

  it("flags a credential written into the command", () => {
    const out = checkCronJobs([job({ command: "select net.http_post('https://x', headers => 'Bearer sk_live_51Habcdefghijk')" })]);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain("database backups");
  });

  it("flags a job running as a superuser, at WARNING", () => {
    const out = checkCronJobs([job({ runs_as: "postgres" })]);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("least-reviewed code");
  });

  it("can report both", () => {
    expect(checkCronJobs([job({ runs_as: "postgres", command: "x sb_secret_abcdefghijklmno" })])).toHaveLength(2);
  });

  it("tolerates an unnamed job", () => {
    expect(checkCronJobs([job({ name: null, runs_as: "postgres" })])[0].consequence).toContain("unnamed");
  });
});

describe("A17 — foreign servers", () => {
  it("is silent when none exist", () => {
    expect(checkForeignServers([])).toEqual([]);
  });

  // A normal architecture, not a vulnerability.
  it("reports at INFO and says it is a note", () => {
    const out = checkForeignServers([{ server: "analytics", wrapper: "postgres_fdw" }]);
    expect(out[0].severity).toBe("INFO");
    expect(out[0].consequence).toContain("note rather than a problem");
    expect(out[0].consequence).toContain("RLS does not apply to the remote side");
  });
});

describe("scanExtensions", () => {
  // Absent input means the query did not run, which is not a clean result.
  it("checks nothing it was not given", () => {
    expect(scanExtensions({})).toEqual([]);
  });

  it("is silent on a real default project", () => {
    expect(
      scanExtensions({ extensions: SUPABASE_DEFAULT, networkGrants: [], cronJobs: [], foreignServers: [] })
    ).toEqual([]);
  });

  it("combines findings across capabilities", () => {
    const out = scanExtensions({
      extensions: [{ name: "postgis", schema: "public" }],
      networkGrants: [{ schema: "net", name: "http_post", grantee: "anon" }],
      cronJobs: [{ name: "j", schedule: "* * * * *", runs_as: "postgres", command: "select 1" }],
      foreignServers: [{ server: "s", wrapper: "postgres_fdw" }],
    });
    expect(out).toHaveLength(4);
    expect(new Set(out.map((x) => x.id)).size).toBe(4);
  });
});

describe("the inventory queries", () => {
  it("pass the read-only guard", () => {
    expect(() => assertReadOnly(EXTENSION_SQL)).not.toThrow();
    expect(() => assertReadOnly(NETWORK_GRANT_SQL)).not.toThrow();
  });

  // Checking the extension exists says nothing about who can call it.
  it("ask about EXECUTE grants, not merely installation", () => {
    expect(NETWORK_GRANT_SQL).toContain("EXECUTE");
    expect(NETWORK_GRANT_SQL).toContain("'anon'");
  });
});
