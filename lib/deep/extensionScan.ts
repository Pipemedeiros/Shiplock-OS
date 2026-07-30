import type { GithubFinding } from "./githubScan";

// A8, A15, A16, A17 — what the database itself is able to do.
//
// Every other database check asks who can read which rows. These ask a different
// question: what can the database REACH, and who can make it reach. A Postgres
// instance that can open outbound HTTP connections, run scheduled jobs, or query
// a remote server is a piece of compute inside the customer's network, and it is
// usually reasoned about as if it were only storage.
//
// Calibrated against a real Supabase project, which ships pg_stat_statements,
// pgcrypto, plpgsql, supabase_vault and uuid-ossp in the `extensions` schema.
// None of that is a finding, and a check that fired on the default install would
// be worthless. Each rule below requires something the platform does NOT do by
// default.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

// ── Inventory queries. Each a single SELECT, so assertReadOnly permits them. ──

export const EXTENSION_SQL = `
select e.extname as name, n.nspname as schema
from pg_extension e join pg_namespace n on n.oid = e.extnamespace
order by 1`;

/**
 * Who may call the functions that make outbound requests.
 *
 * aclexplode over pg_proc is the authoritative answer — checking whether the
 * EXTENSION exists tells you nothing about whether a browser-reachable role can
 * invoke it, and that difference is the whole finding.
 */
export const NETWORK_GRANT_SQL = `
select n.nspname as schema, p.proname as name, r.rolname as grantee
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
join pg_roles r on r.oid = a.grantee
where a.privilege_type = 'EXECUTE'
  and r.rolname in ('anon', 'authenticated')
  and (n.nspname in ('net', 'http') or p.proname in ('http_get', 'http_post', 'http_delete', 'http_put', 'http'))
order by 1, 2`;

export const CRON_JOB_SQL = `
select jobname as name, schedule, username as runs_as, command
from cron.job
order by 1`;

export const FDW_SQL = `
select s.srvname as server, w.fdwname as wrapper
from pg_foreign_server s
join pg_foreign_data_wrapper w on w.oid = s.srvfdw
order by 1`;

// ── Analyzers ──────────────────────────────────────────────────────────────

export interface ExtensionRow { name: string; schema: string }
export interface NetworkGrantRow { schema: string; name: string; grantee: string }
export interface CronJobRow { name: string | null; schedule: string; runs_as: string; command: string }
export interface FdwRow { server: string; wrapper: string }

/** A8 — an extension installed into `public`. */
export function checkExtensionSchemas(rows: ExtensionRow[]): GithubFinding[] {
  const inPublic = rows.filter((r) => r.schema === "public").map((r) => r.name);
  if (inPublic.length === 0) return [];

  return [
    f(
      "extensions:in_public_schema",
      "WARNING",
      `${inPublic.join(", ")} ${inPublic.length === 1 ? "is" : "are"} installed in your public schema`,
      `${inPublic.join(", ")} ${inPublic.length === 1 ? "sits" : "sit"} in the \`public\` schema rather than a dedicated one. Everything in \`public\` is exposed through your API by default, so an extension's functions become callable surface you did not choose to publish. ` +
        `It also makes the extension's names collide with your own tables and functions, which is how a search_path becomes something an attacker can exploit. ` +
        `Supabase installs extensions into \`extensions\` for exactly this reason. Move it: \`alter extension ${inPublic[0]} set schema extensions;\``
    ),
  ];
}

/**
 * A15 — outbound HTTP reachable from a browser-facing role.
 *
 * pg_net being installed is ordinary; Supabase uses it for webhooks. The finding
 * is that `anon` or `authenticated` can EXECUTE it, which turns a public API key
 * into a request originator inside the customer's infrastructure.
 */
export function checkNetworkGrants(rows: NetworkGrantRow[]): GithubFinding[] {
  if (rows.length === 0) return [];

  const roles = [...new Set(rows.map((r) => r.grantee))].sort();
  const functions = [...new Set(rows.map((r) => `${r.schema}.${r.name}`))].sort();

  return [
    f(
      "extensions:network_callable_by_public_role",
      "CRITICAL",
      `Anyone with your public key can make your database send HTTP requests`,
      `${roles.join(" and ")} can execute ${functions.join(", ")}, which open outbound HTTP connections from inside your database. ` +
        `Anyone holding your public key can therefore make your infrastructure issue requests on their behalf. That is server-side request forgery, and the database is an unusually good place to have it: requests come from inside your network, so they reach services that are not exposed to the internet, and cloud metadata endpoints that hand out credentials to whatever asks from inside. ` +
        `It is also a data-exfiltration channel — a request can carry query results in its URL, leaving through a door you opened rather than one you monitor. ` +
        `Fix: \`revoke execute on all functions in schema net from anon, authenticated;\` and call it only from a SECURITY DEFINER function you control, or from your server.`
    ),
  ];
}

/** A16 — scheduled jobs: what runs unattended, as whom. */
export function checkCronJobs(rows: CronJobRow[]): GithubFinding[] {
  if (rows.length === 0) return [];
  const out: GithubFinding[] = [];

  // A literal secret in a job body is readable by anyone who can read cron.job.
  const SECRET_IN_COMMAND = /\b(eyJ[A-Za-z0-9_-]{10,}|sb_secret_[A-Za-z0-9_-]{10,}|sk_live_[A-Za-z0-9]{10,}|bearer\s+[A-Za-z0-9._-]{20,})/i;
  const withSecrets = rows.filter((r) => SECRET_IN_COMMAND.test(r.command ?? ""));

  if (withSecrets.length > 0) {
    out.push(
      f(
        "extensions:cron_secret_in_command",
        "CRITICAL",
        `A scheduled job has a credential written into its command`,
        `${withSecrets.length} scheduled job${withSecrets.length === 1 ? "" : "s"} (${withSecrets.map((r) => r.name ?? "unnamed").join(", ")}) contain${withSecrets.length === 1 ? "s" : ""} what looks like a key or token in the command text itself. ` +
          `Job definitions live in the \`cron.job\` table, so that credential is readable by anything that can read that table, it appears in database backups, and it survives in the job history. Rotating it means editing the job, which is easy to forget. ` +
          `Fix: move the value into Supabase Vault and read it inside the job, so the job body references a secret rather than containing one.`
      )
    );
  }

  const superuserJobs = rows.filter((r) => r.runs_as === "postgres" || r.runs_as === "supabase_admin");
  if (superuserJobs.length > 0) {
    out.push(
      f(
        "extensions:cron_runs_as_superuser",
        "WARNING",
        `${superuserJobs.length} scheduled job${superuserJobs.length === 1 ? "" : "s"} run as a superuser`,
        `${superuserJobs.map((r) => r.name ?? "unnamed").join(", ")} run as \`${superuserJobs[0].runs_as}\`, which bypasses Row Level Security entirely and can alter any table. ` +
          `Sometimes that is required. It is worth confirming deliberately, because a scheduled job is the least-reviewed code in most projects — it runs unattended, its output is rarely read, and a mistake in it has the same reach as a mistake in your migrations. ` +
          `If the job only needs a few tables, give it a role with only those.`
      )
    );
  }

  return out;
}

/** A17 — foreign data wrappers: the database reaching another system. */
export function checkForeignServers(rows: FdwRow[]): GithubFinding[] {
  if (rows.length === 0) return [];

  return [
    f(
      "extensions:foreign_servers",
      "INFO",
      `Your database connects to ${rows.length} external system${rows.length === 1 ? "" : "s"}`,
      `${rows.map((r) => `${r.server} (${r.wrapper})`).join(", ")} ${rows.length === 1 ? "is" : "are"} configured as foreign servers, so your database can query systems outside it. ` +
        `This is a note rather than a problem — it is a normal way to join across services. It is worth knowing about because it widens what a compromise of the database reaches: RLS does not apply to the remote side, and the credentials for that connection live in your database. ` +
        `Worth confirming the connection uses a least-privilege account on the remote system rather than an administrative one.`
    ),
  ];
}

export interface ExtensionInput {
  extensions?: ExtensionRow[];
  networkGrants?: NetworkGrantRow[];
  cronJobs?: CronJobRow[];
  foreignServers?: FdwRow[];
}

/** Every capability check. Absent input means the query did not run — not a pass. */
export function scanExtensions(input: ExtensionInput): GithubFinding[] {
  return [
    ...(input.extensions ? checkExtensionSchemas(input.extensions) : []),
    ...(input.networkGrants ? checkNetworkGrants(input.networkGrants) : []),
    ...(input.cronJobs ? checkCronJobs(input.cronJobs) : []),
    ...(input.foreignServers ? checkForeignServers(input.foreignServers) : []),
  ];
}
