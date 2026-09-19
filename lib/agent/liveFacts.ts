import { loadGraphInput } from "@/lib/graph/graphRun";
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

export interface LiveFact {
  id: string;
  statement: string;
}

/** Variables whose name says they carry a credential. */
const SECRETISH = /(SECRET|PRIVATE_KEY|SERVICE_ROLE|_TOKEN|API_KEY|PASSWORD|CREDENTIAL)/i;
/** Prefixes that declare a variable public on purpose. */
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)/;

/** How many facts may reach the prompt. Ranked, so the cap truncates the tail. */
const MAX_FACTS = 20;

export async function loadLiveFacts(userId: string, repositoryId: string): Promise<LiveFact[]> {
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

  // Public-secret facts first: they are the ones that can carry a finding.
  facts.sort((a, b) => {
    const rank = (f: LiveFact) => (f.id.includes(":public-secret:") ? 0 : 1);
    return rank(a) - rank(b) || a.id.localeCompare(b.id);
  });

  return facts.slice(0, MAX_FACTS);
}
