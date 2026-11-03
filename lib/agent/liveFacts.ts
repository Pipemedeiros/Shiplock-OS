import { loadGraphInput } from "@/lib/graph/graphRun";
import { buildAuthzFacts, type GraphInput } from "@/lib/graph/graph";
import { storeProtects } from "@/lib/graph/attackPaths";
import { loadVerifiedProviderProjects } from "@/lib/deep/providerRepositoryMap";

/**
 * The live half of the reasoning input, flattened into citable statements.
 *
 * The graph stores runtime facts as structured provider data. The agent needs
 * them as short sentences with stable ids, because a hypothesis cites an id and
 * the guard checks that id against what we actually observed. This module is
 * the translation, and it is deliberately the only place that decides which
 * live facts are worth a citation.
 *
 * Two rules hold here:
 *
 *   Ids include provider project identity when recorded. Repository admission
 *   is separate: only observations explicitly associated with this repository
 *   may become facts, and legacy/unmapped observations are excluded.
 *
 *   Values never appear. An environment variable enters as a name and a scope.
 *   "ShipLock never reads your users' data" covers their secrets too, and a
 *   value in a prompt is a value in a log.
 */

interface LiveFact {
  id: string;
  statement: string;
}

/** Variables whose name says they carry a credential. */
const SECRETISH = /(SECRET|PRIVATE_KEY|SERVICE_ROLE|_TOKEN|API_KEY|PASSWORD|CREDENTIAL)/i;
/** Prefixes that declare a variable public on purpose. */
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)/;

/** How many facts may reach the prompt. Ranked, so the cap truncates the tail. */
const MAX_FACTS = 20;

/** Facts from the live stack bound to this repository (database and runtime).
 * Unreadable sources add nothing and never stop the audit. */
export async function loadLiveFacts(userId: string, repositoryId: string): Promise<LiveFact[]> {
  const [database, runtime] = await Promise.all([
    // Optional context, like the runtime half: an unreadable database adds no
    // fact and never stops the source audit.
    loadGraphInput(userId, repositoryId).then(databaseFacts).catch(() => {
      console.error("[liveFacts] Bound database evidence unreadable; database context excluded");
      return [];
    }),
    runtimeFacts(userId, repositoryId),
  ]);
  // An open table first: it is the fact that can carry a finding. Then a
  // public-prefixed credential, then the filtered tables (what lets the
  // verifier refute), then the rest of the host's variables.
  const rank = (f: LiveFact) =>
    f.id.startsWith("db:") && !f.id.endsWith(":rls-filtered") ? 0
      : f.id.includes(":public-secret:") ? 1 : f.id.startsWith("db:") ? 2 : 3;
  return [...database, ...runtime]
    .sort((a, b) => rank(a) - rank(b) || a.id.localeCompare(b.id))
    .slice(0, MAX_FACTS);
}

/**
 * The connected database's own state for the tables this repository's routes
 * reach (X1, 2026-10-12). Only the repository-bound projection counts: a
 * confirmed binding on the current connection, one control-capable transport.
 * A table whose rules were never read states nothing, because unread is not
 * filtered and not open.
 */
function databaseFacts(input: GraphInput): LiveFact[] {
  if (input.correlationScope !== "repository-bound") return [];
  const reached = new Set((input.routes ?? []).flatMap((r) => r.tables)
    .filter((t) => !t.startsWith("rpc:"))
    .map((t) => (t.includes(".") ? t : `public.${t}`)));
  const facts: LiveFact[] = [];
  for (const table of buildAuthzFacts(input).values()) {
    if (!reached.has(table.qualified)) continue;
    const protects = storeProtects(table);
    const q = table.qualified;
    if (protects === false && table.enforced === false) {
      facts.push({ id: `db:${q}:rls-off`, statement: `The connected database reports row level security off on ${q}: the database does not filter which rows of ${q} a query returns.` });
    } else if (protects === false) {
      const roles = table.grantedRoles.length ? table.grantedRoles.join(", ") : "every role it names";
      facts.push({ id: `db:${q}:open-policy`, statement: `The connected database has a policy on ${q} that matches every row, for ${roles}.` });
    } else if (protects === true) {
      facts.push({ id: `db:${q}:rls-filtered`, statement: `The connected database reports row level security on for ${q}, and none of the policies read on it matches every row.` });
    }
  }
  return facts;
}

async function runtimeFacts(userId: string, repositoryId: string): Promise<LiveFact[]> {
  const input = await loadGraphInput(userId);

  // Absent means no runtime collector has ever run for this account. That is
  // different from one running and finding nothing, and the difference must
  // survive: an audit with no connections says so on Coverage rather than
  // reporting a clean live surface it never looked at.
  if (input.runtimeProvidersRead === undefined) return [];
  let verifiedProjects: Set<string>;
  try {
    verifiedProjects = await loadVerifiedProviderProjects(userId, repositoryId);
  } catch {
    // Missing migration or failed optional-provider reads must neither admit
    // context nor prevent the existing source-only audit from running.
    console.error("[liveFacts] Provider repository authorization unavailable; runtime context excluded");
    return [];
  }

  const facts: LiveFact[] = [];

  for (const variable of input.runtimeEnvVars ?? []) {
    // Provider access belongs to the account, not automatically to every repo.
    // Only an explicit association admits the fact into this repository audit.
    if (variable.repositoryId !== repositoryId || !variable.projectId ||
        !variable.connectionFingerprint ||
        !verifiedProjects.has(`${variable.provider}:${variable.projectId}:${variable.connectionFingerprint}`)) continue;

    const scopes = variable.target.length ? variable.target.join(", ") : "no environment";
    const projectId = typeof variable.projectId === "string" && variable.projectId.length > 0
      ? variable.projectId : null;
    const citationPrefix = projectId
      ? `${variable.provider}:project:${encodeURIComponent(projectId)}` : variable.provider;
    const attribution = projectId
      ? `${variable.provider} project ${projectId}`
      : `${variable.provider} (project identity was not recorded)`;

    // A credential-shaped name carried by a public prefix is the one shape
    // worth examining, but its name alone is not proof of browser exposure.
    if (PUBLIC_PREFIX.test(variable.key) && SECRETISH.test(variable.key)) {
      facts.push({
        id: `${citationPrefix}:public-secret:${variable.key}`,
        statement: `${attribution} reports the public-prefixed credential-shaped name ${variable.key} (${scopes}); this does not prove its value shipped to a browser.`,
      });
      continue;
    }

    if (SECRETISH.test(variable.key)) {
      facts.push({
        id: `${citationPrefix}:env:${variable.key}`,
        statement: `${attribution} reports ${variable.key} set in ${scopes}.`,
      });
    }
  }

  return facts;
}
