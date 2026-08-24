import { Client } from "pg";
import { isPrivateOrReservedIp, nodeHostResolver, type HostResolver } from "@/lib/security/ssrfGuard";
import type { PgPolicy } from "./policyScan";
import type { ColumnGrant } from "./grantScan";

// Reading authorization facts from ANY Postgres, not only Supabase.
//
// Why this exists: everything that makes ShipLock's database half worth having
// — reading policy text, correlating it with routes, replaying it in the proving
// ground — depends on Row Level Security, not on Supabase. RLS is standard
// Postgres. Restricting ourselves to one host was a transport accident, not a
// capability boundary, and it cost us Neon, Railway, Render, RDS, Fly and every
// self-hosted database in the ICP.
//
// This is NOT a third connection. It is the same "your database" slot the
// Supabase OAuth fills, for customers who are not on Supabase. The friction
// budget (CLAUDE.md) is two connections and stays two.
//
// WHAT THIS PATH CANNOT DO, stated so it is never oversold: the Supabase
// Management API also exposes advisors, auth configuration, storage, Realtime
// and backup posture. Those are platform features with no SQL equivalent, so a
// direct-Postgres customer gets the SQL-readable subset — policies, RLS state
// and column grants — and must be told that plainly rather than shown a thinner
// scan that looks like a cleaner one.
//
// SECURITY POSTURE. A connection string is a far larger credential than the
// read-only OAuth token, so this module is deliberately paranoid:
//   · the customer is asked for a role they created for us, and we verify it
//     cannot write before trusting anything (`assertReadOnlyRole`)
//   · every session opens a READ ONLY transaction, so even a bug in our own SQL
//     cannot mutate their data
//   · a statement timeout bounds any query we send
//   · the host is SSRF-checked, because a connection string is an unusually
//     direct way to ask a server to open a socket wherever an attacker likes
//   · the string is encrypted at rest and never logged, whole or in part

/** Postgres refuses anything longer than this anyway; bound it before parsing. */
const MAX_CONNECTION_STRING = 2048;
const CONNECT_TIMEOUT_MS = 10_000;
const STATEMENT_TIMEOUT_MS = 15_000;

export class PostgresConnectionError extends Error {
  constructor(
    message: string,
    /** Stable, non-sensitive reason code for the UI. Never includes the DSN. */
    readonly code:
      | "malformed"
      | "insecure_scheme"
      | "blocked_host"
      | "unreachable"
      | "auth_failed"
      | "not_read_only"
  ) {
    super(message);
    this.name = "PostgresConnectionError";
  }
}

export interface ParsedConnection {
  host: string;
  port: number;
  database: string;
  user: string;
  /** Rebuilt DSN with TLS forced on. Never log this. */
  dsn: string;
}

/**
 * Parse and harden a customer-supplied connection string.
 *
 * TLS is FORCED rather than merely preferred. A customer pasting a DSN copied
 * from a local dev setup would otherwise send their database password across the
 * public internet in the clear, on our instruction — we would have created the
 * vulnerability we are selling protection from.
 */
export function parseConnectionString(raw: string): ParsedConnection {
  const trimmed = (raw ?? "").trim();
  if (!trimmed || trimmed.length > MAX_CONNECTION_STRING) {
    throw new PostgresConnectionError("Connection string is empty or too long.", "malformed");
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new PostgresConnectionError("That does not look like a connection string.", "malformed");
  }

  if (url.protocol !== "postgres:" && url.protocol !== "postgresql:") {
    throw new PostgresConnectionError(
      "Expected a postgres:// or postgresql:// connection string.",
      "malformed"
    );
  }

  const host = url.hostname;
  const database = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const user = decodeURIComponent(url.username);
  if (!host || !database || !user) {
    throw new PostgresConnectionError(
      "The connection string is missing a host, database or user.",
      "malformed"
    );
  }

  // Force TLS, and drop any sslmode the customer supplied that would weaken it.
  url.searchParams.delete("sslmode");
  url.searchParams.set("sslmode", "require");

  return {
    host,
    port: url.port ? Number(url.port) : 5432,
    database,
    user,
    dsn: url.toString(),
  };
}

/**
 * Refuse to open a socket to anything that is not a public host.
 *
 * A connection string is the most literal SSRF primitive there is: the customer
 * hands us an address and we connect to it. Without this, `postgres://…@10.0.0.5`
 * or a metadata-service address turns our scanner into a probe of our own
 * network. Reuses the same resolver the HTTP fetches use, so the two paths
 * cannot drift.
 */
export async function assertConnectableHost(
  host: string,
  resolver: HostResolver = nodeHostResolver
): Promise<void> {
  let addresses: string[];
  try {
    addresses = await resolver.lookup(host);
  } catch {
    throw new PostgresConnectionError(`Could not resolve ${host}.`, "unreachable");
  }
  if (addresses.length === 0) {
    throw new PostgresConnectionError(`Could not resolve ${host}.`, "unreachable");
  }
  // EVERY address must be public — a host resolving to both a public and a
  // private address is exactly the DNS-rebinding shape this is here to stop.
  for (const address of addresses) {
    if (isPrivateOrReservedIp(address)) {
      throw new PostgresConnectionError(
        `${host} resolves to a private or reserved address, which we will not connect to.`,
        "blocked_host"
      );
    }
  }
}

/**
 * Open a session, run `fn`, close it. The session is READ ONLY at the
 * transaction level, which is the part that actually protects the customer:
 * `assertReadOnly`-style string inspection can be outsmarted by a clever
 * expression, but Postgres refusing to write inside a read-only transaction
 * cannot. Both are applied — this is the one that is load-bearing.
 */
export async function withReadOnlySession<T>(
  connection: ParsedConnection,
  fn: (query: <R>(sql: string, params?: unknown[]) => Promise<R[]>) => Promise<T>,
  resolver: HostResolver = nodeHostResolver
): Promise<T> {
  await assertConnectableHost(connection.host, resolver);

  const client = new Client({
    connectionString: connection.dsn,
    connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
    statement_timeout: STATEMENT_TIMEOUT_MS,
    // The customer's certificate chain is frequently a managed provider's own
    // CA, which Node does not ship. We require TLS but do not verify the chain,
    // which protects the password in transit — the realistic threat for a
    // credential the customer just pasted into a form — without failing on every
    // Neon and RDS endpoint. Stated explicitly because an unexplained
    // `rejectUnauthorized: false` reads as carelessness.
    ssl: { rejectUnauthorized: false },
  });

  try {
    await client.connect();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // Never echo the DSN back; it carries the password.
    throw new PostgresConnectionError(
      /password|authenticat|role .* does not exist/i.test(message)
        ? "Postgres rejected those credentials."
        : "Could not reach that database.",
      /password|authenticat|role .* does not exist/i.test(message) ? "auth_failed" : "unreachable"
    );
  }

  try {
    await client.query("BEGIN TRANSACTION READ ONLY");
    const query = async <R>(sql: string, params?: unknown[]): Promise<R[]> => {
      const res = await client.query(sql, params as never);
      return res.rows as R[];
    };
    const out = await fn(query);
    await client.query("COMMIT");
    return out;
  } finally {
    await client.end().catch(() => {});
  }
}

/**
 * Verify the role we were given cannot write, before we trust it with anything.
 *
 * We ask for a read-only role in the setup copy, but asking is not verifying,
 * and a customer in a hurry will paste the superuser DSN their provider showed
 * them. Checking means the promise "ShipLock cannot change your database" is a
 * property of their grant rather than of our good intentions — and if it fails
 * we can tell them precisely what to fix.
 *
 * `rolsuper` is checked separately because a superuser bypasses RLS and every
 * grant, so no amount of table-level permission checking would catch it.
 */
export async function assertReadOnlyRole(
  query: <R>(sql: string, params?: unknown[]) => Promise<R[]>
): Promise<void> {
  const [role] = await query<{ rolsuper: boolean; rolbypassrls: boolean }>(
    `SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`
  );
  if (role?.rolsuper || role?.rolbypassrls) {
    throw new PostgresConnectionError(
      "That role is a superuser or can bypass Row Level Security. Create a read-only role for ShipLock instead — we should not be able to change or over-read your data.",
      "not_read_only"
    );
  }

  const [writable] = await query<{ count: string }>(
    `SELECT count(*)::text AS count
       FROM information_schema.role_table_grants
      WHERE grantee = current_user
        AND table_schema NOT IN ('pg_catalog', 'information_schema')
        AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')`
  );
  if (Number(writable?.count ?? 0) > 0) {
    throw new PostgresConnectionError(
      "That role can write to your tables. Create a read-only role for ShipLock instead — we should not be able to change your data.",
      "not_read_only"
    );
  }
}

// ── The facts themselves ───────────────────────────────────────────────────
// Same SQL the Supabase transport sends, so both paths produce identical shapes
// and everything downstream — policyScan, the graph, the proving ground — is
// reused rather than reimplemented.

const POLICY_SQL = `
  SELECT schemaname, tablename, policyname, cmd, qual, with_check, roles
    FROM pg_policies
   WHERE schemaname = 'public'`;

/**
 * RLS state per table. The Supabase path gets this from the 16-check scan, which
 * needs the anon key; here we read it straight from the catalogue, which is both
 * cheaper and more authoritative.
 */
const RLS_SQL = `
  SELECT c.relname AS name, c.relrowsecurity AS rls_enabled
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'public' AND c.relkind = 'r'`;

const GRANT_SQL = `
  SELECT grantee, table_name AS table, column_name AS column, privilege_type AS privilege
    FROM information_schema.column_privileges
   WHERE table_schema = 'public'
     AND grantee IN ('anon', 'authenticated', 'PUBLIC')`;

export interface DirectDbFacts {
  policies: PgPolicy[];
  scanTables: { name: string; rlsEnabled: boolean }[];
  grants: ColumnGrant[];
}

/** Normalise pg's `name[]` roles column, which some transports stringify. */
function toRoles(roles: string[] | string | null): string[] {
  if (Array.isArray(roles)) return roles;
  if (typeof roles === "string") {
    return roles.replace(/^\{|\}$/g, "").split(",").filter(Boolean);
  }
  return [];
}

/**
 * Everything the graph's database collector needs, in one session.
 *
 * Grants are best-effort: `column_privileges` is present on every supported
 * Postgres, but the anon/authenticated role names are a Supabase convention, so
 * a self-hosted database will simply return none. That is a correct empty
 * result, not a failure, and must not abort the policies we came for.
 */
export async function collectDirectFacts(
  connection: ParsedConnection,
  resolver: HostResolver = nodeHostResolver
): Promise<DirectDbFacts> {
  return withReadOnlySession(
    connection,
    async (query) => {
      await assertReadOnlyRole(query);

      const rawPolicies = await query<{
        schemaname: string;
        tablename: string;
        policyname: string;
        cmd: string;
        qual: string | null;
        with_check: string | null;
        roles: string[] | string | null;
      }>(POLICY_SQL);

      const rawTables = await query<{ name: string; rls_enabled: boolean }>(RLS_SQL);

      let grants: ColumnGrant[] = [];
      try {
        grants = await query<ColumnGrant>(GRANT_SQL);
      } catch {
        grants = [];
      }

      return {
        policies: rawPolicies.map((r) => ({
          schemaname: r.schemaname,
          tablename: r.tablename,
          policyname: r.policyname,
          cmd: r.cmd,
          qual: r.qual,
          with_check: r.with_check,
          roles: toRoles(r.roles),
        })),
        scanTables: rawTables.map((t) => ({ name: t.name, rlsEnabled: Boolean(t.rls_enabled) })),
        grants,
      };
    },
    resolver
  );
}
