import type { Severity } from "@/lib/types";
import type { RouteFact } from "./routeInventory";
import {
  buildGraph,
  readAuthPosture,
  tablesForRoute,
  type AssetGraph,
  type AuthzFacts,
  type GraphInput,
  type GraphNode,
} from "./graph";
import { SEVERITY_RANK, vocabulary } from "./providers";

// Variable names that carry a credential, and the prefixes that declare one
// public on purpose. A NEXT_PUBLIC_ variable in the browser build is where it
// belongs, so it is never evidence of anything.
const PUBLIC_PREFIX = /^(NEXT_PUBLIC_|VITE_|PUBLIC_|REACT_APP_)/;
const SECRETISH = /(SECRET|PRIVATE_KEY|SERVICE_ROLE|_TOKEN|API_KEY|PASSWORD|CREDENTIAL)/i;

// The reasoner (PRODUCT-DESIGN.md §5.2). Walks the graph for paths where facts
// from DIFFERENT surfaces combine into something none of them says alone.
//
// The rule that keeps this honest: **every path must span at least two
// collectors.** A permissive policy on its own is already reported by the policy
// scan and by Supabase's own advisor; repeating it here with more adjectives
// would be noise dressed as intelligence. A path earns its place only by saying
// something no single collector could:
//
//   "`invoices` has a policy that filters nothing (database)
//    + /api/invoices reads it with no ownership check (source)
//    + anyone can self-register (auth config)
//    + 40 sources are hitting /login right now (traffic)
//    -> anyone can sign up and read every invoice, and someone is trying."
//
// Ranking is by EXPLOITABILITY, not severity: how few steps, how few
// credentials, how reachable. A critical-severity issue nothing exposes ranks
// below a medium one an anonymous request can reach.

export interface AttackPath {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
  /** Ordered facts that justify the conclusion, each naming its collector. */
  evidence: { collector: "db" | "source" | "config" | "traffic" | "runtime"; fact: string }[];
  /** Higher = more exploitable. Ordering only; never shown as a score. */
  score: number;
  /** Collectors involved. Length >= 2 is enforced. */
  surfaces: string[];
}

function facts(node: GraphNode): AuthzFacts {
  return node.attrs as unknown as AuthzFacts;
}

function routeOf(node: GraphNode): RouteFact & { suspiciousRequests: number } {
  return node.attrs as unknown as RouteFact & { suspiciousRequests: number };
}

/** A route reachable by someone with no credentials at all. */
function isAnonymous(route: RouteFact): boolean {
  return !route.authenticated && !route.machineGated;
}

/**
 * Whether the data store would stop an over-broad query on this asset.
 *
 * `enforced === null` means no database collector ran (a common, legitimate
 * state — no store is connected). That is UNKNOWN, and unknown must not be
 * reported as unprotected: we would be inventing a fact we never observed.
 * Paths that need this return no finding rather than a guess.
 *
 * Provider-neutral by construction: it asks only whether authorization is
 * switched on and whether some rule grants access unconditionally. Both
 * questions have an answer on every engine we model.
 */
function storeProtects(asset: AuthzFacts): boolean | null {
  // Enforcement switched OFF is conclusive on its own: nothing is filtering, and
  // no unread rule could change that. This stays a definite `false` even when
  // the rules were never read.
  if (asset.enforced === false) return false;

  // An unconditional grant is conclusive in the same direction, whatever the
  // enforcement flag says.
  if (asset.unconditionalGrant) return false;

  // Everything below is an ABSENCE of bad news, and absence only means safety if
  // we actually looked. Enforcement on with the rules unread is the case that
  // used to return `true`: we had observed that row security was switched on and
  // inferred, without evidence, that the policies behind it were sound. A
  // `USING (true)` policy lives exactly there — enforcement on, filter absent —
  // and it is the single most common critical finding this product exists to
  // catch. Reporting it as protected was the worst reachable answer.
  if (!asset.rulesRead) return null;

  // Rules were read and none grants unconditionally. Enforcement unknown is
  // still unknown; enforcement on with clean rules is genuinely protected.
  return asset.enforced === true ? true : null;
}

export function findAttackPaths(input: GraphInput): AttackPath[] {
  const graph: AssetGraph = buildGraph(input);
  const posture = readAuthPosture(input.authConfig);
  const paths: AttackPath[] = [];

  for (const node of graph.nodes.values()) {
    if (node.kind !== "route") continue;
    const route = routeOf(node);

    for (const tableNode of tablesForRoute(graph, node.id)) {
      const table = facts(tableNode);
      const protectedByDb = storeProtects(table);
      const words = vocabulary(table.provider);

      // ── Path 1: anonymous reach into an unprotected table ──────────────
      // Two surfaces: source (the route takes no credentials) + db (nothing
      // stops the read). Neither is alarming alone; together it is open data.
      if (isAnonymous(route) && protectedByDb === false) {
        const why = table.enforced === false ? words.notEnforced : words.unconditional;
        paths.push({
          id: `path:anon_read:${route.path}:${table.qualified}`,
          severity: "CRITICAL",
          title: `Anyone on the internet can read ${table.qualified} through ${route.path}`,
          consequence:
            `${route.path} does not identify who is calling it, and it queries ${table.qualified}, where ${why}. ` +
            `Those two facts are each unremarkable on their own — plenty of endpoints are public, and plenty of tables are meant to be readable. Together they mean the contents of ${table.qualified} are available to anyone who sends a request, with no account, no token and no clue left in your logs that it was not a normal user. ` +
            `Fix either half and the path closes: require a session in ${route.file}, or ${words.ownershipRemedy(table.qualified)}. Doing both is better, because each is a single edit away from being wrong again.`,
          evidence: [
            { collector: "source", fact: `${route.path} (${route.file}) resolves no caller identity` },
            { collector: "db", fact: `${table.qualified}: ${why}` },
          ],
          score: 100 + (table.sensitive ? 25 : 0),
          surfaces: ["source", "db"],
        });
        continue;
      }

      // ── Path 2: tenant isolation (A4) ──────────────────────────────────
      // A signed-in user reaching every tenant's rows. The single most damaging
      // bug this ICP ships, and invisible to every tool in isolation: the route
      // looks secure (it authenticates) and the policy looks present.
      if (route.authenticated && !route.ownershipFiltered && protectedByDb === false) {
        const amplified = posture.signupsOpen === true;
        paths.push({
          id: `path:tenant_isolation:${route.path}:${table.qualified}`,
          severity: "CRITICAL",
          title: amplified
            ? `Anyone can sign up and read every row of ${table.qualified}`
            : `Any signed-in user can read every row of ${table.qualified}`,
          consequence:
            `${route.path} does check that the caller is signed in, which is why this looks safe in review — but it never narrows the query to the caller, and ${table.qualified} has no rule that would narrow it either. ` +
            `So the endpoint returns every row to every user, not just their own. ` +
            (amplified
              ? `Sign-ups are open on this project, so the credential needed is a free account anyone can create${posture.autoConfirm ? " with an address they never have to confirm" : ""}. That reduces this from "a customer could" to "anyone could".`
              : `Any existing user can do this to every other user's data.`) +
            ` Fix in ${route.file} by ${words.callerScopeRemedy}, and ${words.ownershipRemedy(table.qualified)} so the store enforces it even if the code changes.`,
          evidence: [
            { collector: "source", fact: `${route.path} authenticates but applies no ownership filter` },
            {
              collector: "db",
              fact: table.unconditionalGrant
                ? `${table.qualified}: ${words.unconditional}`
                : `${table.qualified}: ${words.notEnforced}`,
            },
            ...(amplified
              ? ([{ collector: "config", fact: "Sign-ups are open to anyone" }] as const)
              : []),
          ],
          score: (amplified ? 95 : 80) + (table.sensitive ? 25 : 0),
          surfaces: amplified ? ["source", "db", "config"] : ["source", "db"],
        });
        continue;
      }

      // ── Path 3: service-role route with no ownership filter ────────────
      // The service-role key bypasses RLS entirely, so the database cannot help
      // here no matter how good the policies are — the code is the only control.
      if (route.usesServiceRole && !route.ownershipFiltered && !isAnonymous(route) && table.sensitive) {
        paths.push({
          id: `path:service_role_unscoped:${route.path}:${table.qualified}`,
          severity: "WARNING",
          title: `${route.path} reads ${table.qualified} with ${words.mechanism} bypassed and no ownership check`,
          consequence:
            `${route.path} ${words.bypassNote.replace("the table", table.qualified)}. ` +
            `That is a legitimate thing to do, but it moves the entire burden of deciding who may see which rows into ${route.file}, and we could not find a filter there scoping the query to the caller. ` +
            `If that filter is genuinely missing, this endpoint returns other people's data. If it is applied in a way we cannot see, this is worth confirming rather than assuming — the store will not catch a mistake here, because you have told it not to.`,
          evidence: [
            {
              collector: "source",
              fact: `${route.path} reaches the store with an authorization-bypassing credential and no ownership filter`,
            },
            { collector: "db", fact: `${table.qualified} holds data that identifies people` },
          ],
          score: 60,
          surfaces: ["source", "db"],
        });
        continue;
      }

      // ── Path 4: anonymous route reaching a sensitive table, RLS unknown ─
      // Reported at a lower severity BECAUSE the database half is unknown. It is
      // still worth saying: an unauthenticated endpoint touching a table full of
      // people is a thing to look at, and we say plainly what we could not check.
      if (isAnonymous(route) && protectedByDb === null && table.sensitive) {
        paths.push({
          id: `path:anon_sensitive_unknown:${route.path}:${table.qualified}`,
          severity: "WARNING",
          title: `${route.path} is public and reads ${table.qualified}`,
          consequence:
            `${route.path} takes no credentials and queries ${table.qualified}, which looks like it holds personal data. Whether that is safe depends entirely on the access rules on that table, and we have not been able to read them — connect your database and we will check, and either close this or escalate it. ` +
            `We are telling you now rather than after, because a public endpoint over personal data is worth a look even before we can confirm the store side.`,
          evidence: [
            { collector: "source", fact: `${route.path} resolves no caller identity` },
            { collector: "db", fact: `Access rules on ${table.qualified} not yet readable` },
          ],
          score: 40,
          surfaces: ["source", "db"],
        });
      }
    }
  }

  // ── Traffic corroboration ────────────────────────────────────────────────
  // Traffic never creates a path; it raises one that already exists. "Someone is
  // trying this right now" changes urgency, not truth, and inventing a finding
  // from traffic alone would be exactly the false-alarm behaviour we avoid.
  const hotTotal = (input.trafficHotPaths ?? []).reduce((sum, h) => sum + h.suspiciousRequests, 0);
  if (hotTotal > 0 && paths.length > 0) {
    const busiest = [...(input.trafficHotPaths ?? [])].sort(
      (a, b) => b.suspiciousRequests - a.suspiciousRequests
    )[0];
    for (const path of paths) {
      if (path.severity !== "CRITICAL") continue;
      path.score += 30;
      path.surfaces = [...new Set([...path.surfaces, "traffic"])];
      path.evidence.push({
        collector: "traffic",
        fact: `${busiest.suspiciousRequests} suspicious requests to ${busiest.path} in the last 48h`,
      });
      path.consequence +=
        ` We are also seeing ${busiest.suspiciousRequests} suspicious requests to ${busiest.path} in the last 48 hours. That does not mean this specific path has been used, and we are not claiming a breach — but it does mean the account-creation and login surface is under active automated attention, so this is worth doing today rather than this month.`;
    }
  }

  // ── Runtime corroboration ────────────────────────────────────────────────
  // A server secret that the host also exposes to the browser build. The code
  // half cannot see this: a repository names the variable it expects, and only
  // the host knows which environments it was scoped to. The runtime half cannot
  // see it either, because "this variable is public" is unremarkable until you
  // know a route reads it as a server credential.
  //
  // Like traffic, this raises an existing path rather than inventing one. The
  // difference from traffic is that it is a configuration fact rather than an
  // observation, so it raises the finding's standing as evidence rather than
  // only its urgency.
  const exposedServerVars = (input.runtimeEnvVars ?? []).filter(
    (v) => !PUBLIC_PREFIX.test(v.key) && SECRETISH.test(v.key) && v.target.includes("production"),
  );

  if (exposedServerVars.length > 0 && paths.length > 0) {
    const worst = exposedServerVars[0];
    for (const path of paths) {
      if (path.severity !== "CRITICAL") continue;
      path.score += 20;
      path.surfaces = [...new Set([...path.surfaces, "runtime"])];
      path.evidence.push({
        collector: "runtime",
        fact: `${worst.provider} reports ${worst.key} present in the production environment`,
      });
    }
  }

  // Enforce the two-surface rule structurally, not just by convention.
  const multiSurface = paths.filter((p) => new Set(p.surfaces).size >= 2);

  return multiSurface.sort(
    (a, b) =>
      b.score - a.score ||
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.id.localeCompare(b.id)
  );
}
