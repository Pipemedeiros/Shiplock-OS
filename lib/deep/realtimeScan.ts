import type { GithubFinding } from "./githubScan";

// A14 — Realtime authorisation, and A20 — custom JWT claim hooks.
//
// A14 is the check CHECK-SPEC.md notes nobody performs, and the reason it gets
// missed is structural: Realtime is a SECOND read path into the same tables, and
// it is configured somewhere else entirely. A developer secures their REST
// surface, tests it, and never thinks about the fact that adding a table to the
// `supabase_realtime` publication opened a websocket streaming every INSERT,
// UPDATE and DELETE on it.
//
// Realtime does respect RLS — but only when RLS exists. A published table with
// RLS off streams every change to anyone who subscribes with the anon key. Not a
// snapshot they have to ask for: a live feed of the table as it changes, which
// is strictly worse than a leaky SELECT because it arrives continuously and
// leaves no query in any log the developer reads.
//
// A20 covers auth hooks. A custom access-token hook writes claims INTO the JWT
// that policies then trust. If that function is writable, or runs with a
// search_path an attacker can influence, it becomes a way to mint your own
// claims — privilege escalation that every downstream policy honours, because
// from their point of view the token is legitimately signed.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

/** Tables published to Realtime, with their RLS state and policy count. */
export const REALTIME_SQL = `
select pt.schemaname as schema,
       pt.tablename as name,
       c.relrowsecurity as rls_enabled,
       (select count(*) from pg_policies p
         where p.schemaname = pt.schemaname and p.tablename = pt.tablename) as policy_count
from pg_publication_tables pt
join pg_class c on c.relname = pt.tablename
join pg_namespace n on n.oid = c.relnamespace and n.nspname = pt.schemaname
where pt.pubname = 'supabase_realtime'
order by 1, 2`;

/** Auth hook functions and how they are defined. */
export const AUTH_HOOK_SQL = `
select n.nspname as schema,
       p.proname as name,
       p.prosecdef as security_definer,
       coalesce(array_to_string(p.proconfig, ','), '') as config
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where p.proname ilike '%hook%' and n.nspname not in ('pg_catalog', 'information_schema')
order by 1, 2`;

export interface RealtimeTableRow {
  schema: string;
  name: string;
  rls_enabled: boolean;
  policy_count: number;
}

export interface AuthHookRow {
  schema: string;
  name: string;
  security_definer: boolean;
  config: string;
}

/**
 * A14 — a table streaming to anyone who subscribes.
 *
 * Two states, and they are different problems. RLS off means every change goes
 * to every subscriber. RLS on with NO policies means the opposite — Realtime
 * delivers nothing — which is safe but usually not what the developer intended,
 * so it is reported as a note rather than a risk.
 */
export function checkRealtimeTables(rows: RealtimeTableRow[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  const unprotected = rows.filter((r) => !r.rls_enabled);
  if (unprotected.length > 0) {
    const names = unprotected.map((r) => `${r.schema}.${r.name}`).sort();
    out.push(
      f(
        "realtime:published_without_rls",
        "CRITICAL",
        `${names.join(", ")} ${names.length === 1 ? "is" : "are"} streaming live to anyone who subscribes`,
        `${names.join(", ")} ${names.length === 1 ? "is" : "are"} published to Supabase Realtime with Row Level Security switched off. ` +
          `Anyone holding your public key can open a websocket and receive every insert, update and delete on ${names.length === 1 ? "that table" : "those tables"} as it happens. ` +
          `This is worse than a table that merely reads openly, for two reasons. It is a continuous feed rather than a query someone has to think to run; they subscribe once and watch. And it produces no request in the logs you look at, so nothing about it will ever catch your eye. ` +
          `It is also easy to miss because Realtime is configured somewhere else: securing your API surface does nothing here, and adding a table to the publication is a single toggle. ` +
          `Fix: \`alter table ${names[0]} enable row level security;\` and add a policy scoping rows to their owner. Realtime honours policies; it just has nothing to honour right now.`
      )
    );
  }

  const silent = rows.filter((r) => r.rls_enabled && r.policy_count === 0);
  if (silent.length > 0) {
    const names = silent.map((r) => `${r.schema}.${r.name}`).sort();
    out.push(
      f(
        "realtime:published_but_denied",
        "INFO",
        `${names.join(", ")} ${names.length === 1 ? "is" : "are"} published to Realtime but deliver nothing`,
        `${names.join(", ")} ${names.length === 1 ? "is" : "are"} in the Realtime publication with Row Level Security on and no policies, so the database denies everything and subscribers receive no events. ` +
          `That is the safe direction, and nothing is leaking. It is here because it is usually not what was intended; someone enabled Realtime expecting a live feed, and it silently does nothing. ` +
          `If the feed is meant to work, add a policy that scopes rows to their owner. If it is not, removing the table from the publication makes the intent clear.`
      )
    );
  }

  return out;
}

/**
 * A20 — auth hooks that shape the token policies trust.
 *
 * A hook without a pinned search_path is the finding. `search_path` decides
 * which schema an unqualified name resolves to, so a function without one can be
 * made to call a different function than its author meant — and this particular
 * function decides what claims end up in a signed token.
 */
export function checkAuthHooks(rows: AuthHookRow[]): GithubFinding[] {
  const risky = rows.filter((r) => r.security_definer && !/search_path=/i.test(r.config));
  if (risky.length === 0) return [];

  const names = risky.map((r) => `${r.schema}.${r.name}`).sort();

  return [
    f(
      "auth_hook:mutable_search_path",
      "WARNING",
      `${names.join(", ")} runs with elevated rights and no fixed search_path`,
      `${names.join(", ")} ${names.length === 1 ? "is" : "are"} SECURITY DEFINER (running with the definer's privileges rather than the caller's) and ${names.length === 1 ? "does" : "do"} not pin a search_path. ` +
        `search_path decides which schema an unqualified name resolves to, so anyone who can create a function or table in an earlier schema can make this one call something its author never wrote, with elevated rights. ` +
        `That matters more here than for an ordinary function, because a hook with "hook" in its name is usually shaping the claims that go into a signed access token. Claims are what your policies trust: if this can be influenced, so can every rule written as "admins can read everything". ` +
        `Fix: add \`set search_path = ''\` to the function definition and schema-qualify every name inside it.`
    ),
  ];
}

export interface RealtimeInput {
  realtimeTables?: RealtimeTableRow[];
  authHooks?: AuthHookRow[];
}

/** A14 + A20. Absent input means the query did not run, which is not a pass. */
export function scanRealtimeAndHooks(input: RealtimeInput): GithubFinding[] {
  return [
    ...(input.realtimeTables ? checkRealtimeTables(input.realtimeTables) : []),
    ...(input.authHooks ? checkAuthHooks(input.authHooks) : []),
  ];
}
