import type { GithubFinding } from "@/lib/deep/githubScan";
import type { RouteFact } from "./routeInventory";

// C12 / C13 — findings the route inventory already has the facts for.
//
// The inventory was built as a collector for the graph, and the graph uses it to
// find multi-surface attack paths. But two of the facts it records are worth
// reporting on their own, without needing a database fact to correlate with:
// an endpoint that identifies nobody, and one that accepts anything.
//
// The bar for reporting alone is that the finding must stand up WITHOUT the
// database half. "This route reads a table and nothing checks who is calling" is
// only alarming if the table matters. "This route WRITES based on a request body
// it never validates" is a problem regardless of what the policies say.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);

/**
 * C12 — a route that changes data without identifying the caller.
 *
 * Restricted to MUTATING methods on purpose. A public GET is ordinary — most
 * apps have several, and flagging them all would bury the one that matters. A
 * public POST that writes to a table is a different thing: whatever it does, it
 * does for anyone who finds the URL.
 */
export function checkUnauthenticatedMutations(routes: RouteFact[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const route of routes) {
    if (route.authenticated || route.machineGated) continue;
    const mutating = route.methods.filter((m) => MUTATING.has(m));
    if (mutating.length === 0) continue;
    // Touching no table at all is usually a health check or a redirect.
    if (route.tables.length === 0) continue;

    // We could not read how this route decides who is calling, so we cannot
    // say it accepts writes "from anyone". Named as our gap, at a severity that
    // matches what we actually know, rather than dropped -- an endpoint we
    // could not judge is worth a sentence.
    if (!route.identityReadable) {
      out.push(
        f(
          `github:unreadable_mutation:${route.path}`,
          "WARNING",
          `${route.path} accepts ${mutating.join("/")} and we could not read what guards it`,
          `${route.path} writes to ${route.tables.slice(0, 3).join(", ")}, and ${route.identityGap}. ` +
            `That means we cannot tell you whether this endpoint is protected, not that it is unprotected. ` +
            `Open ${route.file} and confirm the caller is checked before the write.`,
        ),
      );
      continue;
    }

    out.push(
      f(
        `github:unauthenticated_mutation:${route.path}`,
        "CRITICAL",
        `${route.path} accepts ${mutating.join("/")} from anyone and touches your data`,
        `${route.path} does not identify who is calling it (no session, no token, no signature) and it reaches ${route.tables.join(", ")}. ` +
          `Anyone who finds the URL can call it, and there will be nothing in your logs distinguishing them from a real user. ` +
          `Public GET endpoints are ordinary and we do not flag them; this is flagged because it is a ${mutating.join("/")}, so whatever it does to your data, it does on request from strangers. ` +
          `If it is meant to be public (a webhook, an ingest endpoint) it still needs to verify a shared secret or signature. If it is not, resolve the caller's session in ${route.file} before doing anything else.`
      )
    );
  }

  return out;
}

/**
 * C13 — mass assignment: a request body written to the database wholesale.
 *
 * The first version of this check asked "is there a schema library?" and ran at a
 * 100% false-positive rate against our own codebase — it flagged a route that
 * validates by hand with `typeof x === "string"`, one that reads a single field
 * with a default, and the Stripe webhook, whose body is signature-verified and
 * whose shape is Stripe's. "No zod" is not a vulnerability.
 *
 * The actual risk is narrower and worth naming precisely: the parsed body object
 * reaching `.insert()` / `.update()` / `.upsert()` as a whole. Then a caller who
 * adds a field you never intended — `role`, `is_admin`, `user_id` — writes it,
 * because nothing enumerated what was allowed. That is a real bug with a real
 * shape, and it is detectable without guessing.
 */
const BODY_BINDING = /(?:const|let|var)\s*\{?\s*([A-Za-z_$][\w$]*)\s*\}?\s*=\s*(?:await\s+)?\w+\.(?:json|formData)\s*\(/g;
const VALIDATION_HINTS =
  /\b(z\.object|zod|safeParse|yup\.|joi\.|valibot|superstruct|ajv|typia)\b/i;

export function checkUnvalidatedInput(
  routes: RouteFact[],
  sourceOf: (file: string) => string | undefined
): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const route of routes) {
    if (route.methods.filter((m) => MUTATING.has(m)).length === 0) continue;
    if (route.tables.length === 0) continue;

    const src = sourceOf(route.file);
    // Unknown is never a finding.
    if (src === undefined) continue;
    if (VALIDATION_HINTS.test(src)) continue;

    // Which identifier holds the parsed body?
    BODY_BINDING.lastIndex = 0;
    const names = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = BODY_BINDING.exec(src)) !== null) names.add(m[1]);
    // A destructured body (`const { name } = await req.json()`) enumerates its
    // own fields, which is exactly the safe pattern — the binding regex captures
    // the first name, so require the identifier to be used WHOLE below.
    if (names.size === 0) continue;

    const wholesale = [...names].some((name) =>
      new RegExp(`\\.(insert|update|upsert)\\s*\\(\\s*(?:\\[\\s*)?(?:${name}\\b|\\{\\s*\\.\\.\\.\\s*${name}\\b)`).test(src)
    );
    if (!wholesale) continue;

    out.push(
      f(
        `github:mass_assignment:${route.path}`,
        "WARNING",
        `${route.path} writes the whole request body to ${route.tables.join(", ")}`,
        `${route.path} parses a request body and passes it straight into a database write, without listing which fields are allowed. ` +
          `Whatever a caller sends gets written. If your table has a column the user is not supposed to control (role, is_admin, plan, user_id, credits) someone can set it by adding it to the JSON, and the request looks completely ordinary in your logs. ` +
          `We flag this rather than the absence of a validation library, because hand-written checks are fine and common; it is passing the object through WHOLE that creates the problem. ` +
          `Fix in ${route.file} by building the object you write explicitly from the fields you expect, rather than forwarding the parsed body.`
      )
    );
  }

  return out;
}

/** Both route-level checks. */
export function scanRouteFacts(
  routes: RouteFact[],
  sourceOf: (file: string) => string | undefined = () => undefined
): GithubFinding[] {
  return [...checkUnauthenticatedMutations(routes), ...checkUnvalidatedInput(routes, sourceOf)];
}
