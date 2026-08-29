import { loadGraphInput } from "@/lib/graph/graphRun";

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
 *   Ids are stable across runs. `vercel:env:STRIPE_SECRET_KEY` names the same
 *   fact tomorrow, so a finding built on it keeps its identity and the diff
 *   engine does not re-alert it every pass.
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

export async function loadLiveFacts(userId: string): Promise<LiveFact[]> {
  const input = await loadGraphInput(userId);

  // Absent means no runtime collector has ever run for this account. That is
  // different from one running and finding nothing, and the difference must
  // survive: an audit with no connections says so on Coverage rather than
  // reporting a clean live surface it never looked at.
  if (input.runtimeProvidersRead === undefined) return [];

  const facts: LiveFact[] = [];

  for (const variable of input.runtimeEnvVars ?? []) {
    const scopes = variable.target.length ? variable.target.join(", ") : "no environment";

    // A credential-shaped name carried by a public prefix is the one shape
    // worth a citation on its own: the host is telling us it ships to the
    // browser, and only the code half knows it is read as a server secret.
    if (PUBLIC_PREFIX.test(variable.key) && SECRETISH.test(variable.key)) {
      facts.push({
        id: `${variable.provider}:public-secret:${variable.key}`,
        statement: `${variable.provider} exposes ${variable.key} to the browser build (${scopes}), and its name says it is a credential`,
      });
      continue;
    }

    if (SECRETISH.test(variable.key)) {
      facts.push({
        id: `${variable.provider}:env:${variable.key}`,
        statement: `${variable.provider} reports ${variable.key} set in ${scopes}`,
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
