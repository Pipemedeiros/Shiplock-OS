import type { GithubFinding } from "./githubScan";
import { classifyColumn } from "@/lib/exposure/model";

// A5 — column-level grants to `anon` and `authenticated`.
//
// We shipped this bug ourselves (migration 035), which is the best argument for
// checking it. `anon` and `authenticated` held SELECT + INSERT + UPDATE on EVERY
// column of user_profiles, including encrypted API tokens and the `is_paid` flag.
//
// It was not exploitable as it stood — RLS was on and there was no UPDATE policy,
// so the database denied writes regardless of the grant. That is exactly what
// makes this class worth reporting and easy to dismiss: it is invisible in every
// test, it survives every review that looks at policies, and it is ONE
// reasonable-sounding policy away from critical. The moment someone adds "users
// can update own profile", every column becomes user-writable, including the one
// that decides whether they have paid.
//
// The framing that follows from that, and which the copy holds to: grants and
// policies should not have to be correct TOGETHER for a table to be safe. Two
// independent things each have to be wrong before data moves. A finding here is
// about removing a dependency between them, not about an active breach.
//
// Grants also silently widen over time. A table-level grant is inherited by every
// column added afterwards, so each migration that adds a column re-widens the
// exposure without anyone touching the grant.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

export interface ColumnGrant {
  grantee: string;
  table: string;
  column: string;
  privilege: string; // SELECT | INSERT | UPDATE | REFERENCES | ...
}

/** The two roles a browser can reach with a public key. */
const PUBLIC_ROLES = new Set(["anon", "authenticated"]);
const WRITE_PRIVILEGES = new Set(["INSERT", "UPDATE", "DELETE"]);

/**
 * Columns that decide entitlement rather than describe the user.
 *
 * Separated from the PII classifier on purpose: leaking `email` is a privacy
 * problem, writing `is_paid` is a revenue one, and the second is the one a
 * customer will not think to look for.
 */
const ENTITLEMENT_RE =
  /\b(is_paid|is_admin|is_superuser|role|roles|plan|tier|subscription_status|credits|balance|quota|paid_until|trial_ends|permissions|entitlement\w*|verified|approved|banned|disabled)\b/i;

export function isEntitlementColumn(column: string): boolean {
  return ENTITLEMENT_RE.test(column);
}

/**
 * SQL for the grant inventory. A single SELECT, so it passes assertReadOnly.
 *
 * information_schema.column_privileges is the authoritative view, and querying
 * it is precisely what CLAUDE.md tells us to do after any migration — "verify
 * against information_schema.column_privileges after applying, not just that the
 * migration succeeded without error".
 */
export const GRANT_INVENTORY_SQL = `
select grantee, table_name, column_name, privilege_type
from information_schema.column_privileges
where table_schema = 'public'
  and grantee in ('anon', 'authenticated')
order by table_name, column_name`;

export function analyzeGrants(grants: ColumnGrant[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  // table -> role -> details
  type Detail = { writes: Set<string>; entitlement: Set<string>; credentials: Set<string> };
  const byTable = new Map<string, Map<string, Detail>>();

  for (const g of grants) {
    const grantee = g.grantee?.toLowerCase();
    if (!grantee || !PUBLIC_ROLES.has(grantee)) continue;
    if (!g.table || !g.column) continue;

    const roles = byTable.get(g.table) ?? new Map<string, Detail>();
    const detail = roles.get(grantee) ?? { writes: new Set(), entitlement: new Set(), credentials: new Set() };

    const priv = (g.privilege ?? "").toUpperCase();
    if (WRITE_PRIVILEGES.has(priv)) {
      detail.writes.add(g.column);
      if (isEntitlementColumn(g.column)) detail.entitlement.add(g.column);
    }
    // A credential readable by anon is a different and worse problem than one
    // that is merely writable.
    if (classifyColumn(g.column)?.category === "credential") detail.credentials.add(g.column);

    roles.set(grantee, detail);
    byTable.set(g.table, roles);
  }

  for (const [table, roles] of byTable) {
    for (const [role, detail] of roles) {
      if (detail.credentials.size > 0) {
        out.push(
          f(
            `grants:credential_readable:${role}:${table}`,
            "CRITICAL",
            `${role} is granted access to credential columns in ${table}`,
            `The \`${role}\` role — which anyone holding your public key can act as — has column privileges on ${[...detail.credentials].sort().join(", ")} in ${table}. Those columns hold tokens or keys. ` +
              `Row Level Security may be stopping the reads today, and if a policy is doing that then nothing is leaking right now. But it means two separate things both have to stay correct for these secrets to stay secret, and only one of them is visible in your policy list. ` +
              `Revoke the grant: \`revoke all on public.${table} from ${role};\` then grant back only the columns the browser genuinely needs. Secrets should be unreachable because there is no grant, not because a policy happens to filter them out.`
          )
        );
      }

      if (detail.entitlement.size > 0) {
        out.push(
          f(
            `grants:entitlement_writable:${role}:${table}`,
            "CRITICAL",
            `${role} can be granted writes to ${[...detail.entitlement].sort().join(", ")} in ${table}`,
            `\`${role}\` holds write privileges on ${[...detail.entitlement].sort().join(", ")} in ${table} — columns that decide what a user is entitled to rather than describing them. ` +
              `If RLS currently has no UPDATE policy on this table then nothing can be written today, and this is not an active breach. It is a dependency: the day someone adds a policy as ordinary as "users can update their own profile", these columns become user-writable too, and a customer can grant themselves whatever ${[...detail.entitlement][0]} means. ` +
              `That is a self-serve upgrade with no code change on your side and nothing unusual in your logs. ` +
              `Fix: revoke write privileges on this table and grant them back per column, so a future policy cannot widen more than you intended.`
          )
        );
        continue;
      }

      // Broad writes without an entitlement column: lower severity, same shape.
      if (detail.writes.size >= 5) {
        out.push(
          f(
            `grants:broad_write:${role}:${table}`,
            "WARNING",
            `${role} holds write privileges on ${detail.writes.size} columns of ${table}`,
            `\`${role}\` can write ${detail.writes.size} columns in ${table}. Whether anything can actually be written depends entirely on your RLS policies, so this may be harmless today. ` +
              `It is worth tightening because grants widen silently: a table-level grant is inherited by every column added afterwards, so each migration that adds a column re-widens this without anyone editing a grant. ` +
              `Granting per column instead means new columns start closed.`
          )
        );
      }
    }
  }

  return out.sort((a, b) => a.id.localeCompare(b.id));
}
