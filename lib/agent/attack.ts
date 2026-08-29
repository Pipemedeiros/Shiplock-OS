import Anthropic from "@anthropic-ai/sdk";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { guardHypotheses, type GuardResult, type ReconIndex } from "./attackGuard";
import { domainPromptLines, type DomainModel } from "./domain";
import type { StackReport } from "./stack";

/**
 * The proposing half of the repository agent.
 *
 * Strix runs an agent that attacks a target and proves what it finds with a
 * working exploit. We keep the reasoning and refuse the exploitation: the
 * target here is a customer's production application, and running an attack
 * against it is out of bounds no matter how good the finding would be.
 *
 * So this agent reads what we collected -- the route inventory, the schema, the
 * stack -- and proposes where an attacker would push. Everything it returns
 * passes through attackGuard.ts, which throws away anything citing a route,
 * file or table we did not actually observe. Proof, where it is possible at
 * all, happens later and elsewhere: lib/proving/* reproduces a finding on a
 * disposable replica seeded with synthetic tenants.
 *
 * Cost: one call per audit, batched over every entry point. Routine monitoring
 * passes still call Claude zero times (lib/monitoring/findings.ts).
 */

const HAIKU = "claude-haiku-4-5-20251001";
const SONNET = "claude-sonnet-4-6";

/** Above this many interesting entries the reasoning is worth the better model. */
const SONNET_ENTRY_THRESHOLD = 25;

const SYSTEM = [
  "You are a security engineer reading an inventory of a web application.",
  "Propose where an attacker would find a way to reach data they should not.",
  "Rules: cite only routes, files, tables and live fact ids present in the input. Never invent one.",
  "Prefer authorization gaps between tenants over generic advice.",
  "id=machine means we FOUND a verified shared secret or signature check in that",
  "route's own code, such as a Stripe constructEvent or an HMAC comparison. Never",
  "report a machine route as missing signature or authentication verification: we",
  "read the check. Absence of a detail in this inventory is not evidence of a",
  "missing control, and a finding that speculates past what is listed is discarded.",
  "entry is the route path exactly as listed under 'routes', never a file path.",
  "Lines under 'live' are facts read from the customer's providers, each starting",
  "with its id. To use one, put the id verbatim in citedFacts. Only a finding with",
  "no route at all, such as a leaked credential, uses that id as its entry instead.",
  "Copy routes and ids exactly; a shortened or reworded one is discarded.",
  "Return JSON only: an array of",
  '{entry, attackClass, title, consequence, citedFiles[], citedTables[], citedFacts[]}.',
  "attackClass is one of: missing_authorization, missing_authentication,",
  "unsigned_webhook, secret_exposure, server_boundary_crossed, injection,",
  "unsafe_redirect, mass_assignment.",
  "No prose, no markdown, no explanation. Empty array if nothing stands out.",
].join(" ");

export interface AgentInput {
  routes: RouteFact[];
  stack: StackReport;
  tables: string[];
  files: string[];
  /**
   * What this business is, read from its own schema. Optional so every existing
   * caller and test keeps working; when present it changes what the model looks
   * FOR rather than merely what it knows.
   */
  domain?: DomainModel;
  /**
   * Live provider facts observed this run, as `{ id, statement }`.
   *
   * These are the half of the system that is not in the repository. They enter
   * the prompt as citable evidence and the guard checks every id the model
   * returns against this list, so a provider fact is a location in exactly the
   * way a file is.
   */
  liveFacts?: { id: string; statement: string }[];
}

export interface AgentOutcome extends GuardResult {
  model: string;
  /** True when the model was never called -- no key, or nothing worth asking. */
  skipped: boolean;
  skipReason?: string;
}

/**
 * Compresses the inventory into something worth a token.
 *
 * Only routes that touch data are described: an endpoint reaching no table
 * cannot leak one, and spending prompt on it crowds out the routes that can.
 */
/** How many routes fit in the prompt before the token budget bites. */
export const MAX_PROMPT_ROUTES = 60;

/**
 * Risk order, for deciding what survives truncation.
 *
 * The prompt holds sixty routes. A repository with more than sixty
 * data-touching routes therefore has some that the agent never sees, and which
 * ones were decided by the order the tar file happened to be in -- so an
 * anonymous, unscoped route over a sensitive table could be invisible because
 * its filename sorted late. That is silence in the direction that hides, and
 * this repository has shipped that bug three times already.
 *
 * Lower score = looked at first. The ordering is the product's own threat
 * model, in one function:
 *   no identity at all, reading data, nothing narrowing it   — the open door
 *   an identity, but nothing narrowing it                    — the tenant gap
 *   everything else                                          — context
 */
export function routeRisk(route: RouteFact, sensitive: Set<string>): number {
  const anonymous = !route.authenticated && !route.machineGated;
  const unscoped = !route.ownershipFiltered;
  const touchesSensitive = route.tables.some((t) => sensitive.has(t));

  if (anonymous && unscoped && touchesSensitive) return 0;
  if (anonymous && unscoped) return 1;
  if (route.authenticated && unscoped && touchesSensitive) return 2;
  if (route.authenticated && unscoped) return 3;
  if (anonymous) return 4;
  if (route.machineGated && unscoped) return 5;
  return 6;
}

export function rankRoutes(routes: RouteFact[], sensitive: Set<string> = new Set()): RouteFact[] {
  return [...routes].sort((a, b) => {
    const byRisk = routeRisk(a, sensitive) - routeRisk(b, sensitive);
    // Path as the tiebreak, so the same repository produces the same prompt
    // twice. A prompt that reorders between runs makes a finding appear and
    // disappear for no reason the customer can see.
    return byRisk !== 0 ? byRisk : a.path.localeCompare(b.path);
  });
}

export function buildPrompt(input: AgentInput): string {
  const interesting = input.routes.filter((r) => r.tables.length > 0);
  const sensitive = new Set(input.domain?.sensitive ?? []);
  const ranked = rankRoutes(interesting, sensitive);
  const shown = ranked.slice(0, MAX_PROMPT_ROUTES);

  const routeLines = shown.map((r) => {
    // "machine" is stated as a verified observation rather than a bare label:
    // MACHINE_GATE_RE matched a real signature or shared-secret check in this
    // route's code. Rendering it as a plain tag let the model read it as "no
    // user session" and then speculate that no signature check existed, which
    // reported our own Stripe webhook, which verifies via constructEvent, as
    // unsigned.
    const identity = r.machineGated
      ? "machine-verified"
      : r.authenticated
        ? "user"
        : "anonymous";
    const scoped = r.ownershipFiltered ? "scoped" : "unscoped";
    return `${r.path} [${r.methods.join(",") || "GET"}] id=${identity} ${scoped} tables=${r.tables.join(",")} file=${r.file}`;
  });

  const stackLine = input.stack.tools
    .filter((t) => t.kind === "auth" || t.kind === "database" || t.kind === "payments")
    .map((t) => `${t.kind}:${t.name}`)
    .join(" ");

  return [
    stackLine ? `stack ${stackLine}` : "stack unidentified",
    // The business lines come FIRST: they are the frame the routes are read
    // through, and a model that reads them last has already formed an opinion.
    ...(input.domain ? domainPromptLines(input.domain) : []),
    `tables ${input.tables.slice(0, 40).join(",")}`,
    // Live provider facts, with the ids the model must cite to use one. Capped
    // for the same reason routes are: prompt spent here is prompt not spent on
    // the routes that can actually leak something.
    ...(input.liveFacts?.length
      ? ["live", ...input.liveFacts.slice(0, 20).map((f) => `${f.id} ${f.statement}`)]
      : []),
    "routes",
    ...routeLines,
  ].join("\n");
}

/** Routes that did not fit in the prompt, so coverage can say so out loud. */
export function routesOmitted(input: AgentInput): number {
  const interesting = input.routes.filter((r) => r.tables.length > 0);
  return Math.max(0, interesting.length - MAX_PROMPT_ROUTES);
}

/** Pulls the JSON array out of a model response that may be fenced or padded. */
export function extractJsonArray(text: string): unknown {
  const start = text.indexOf("[");
  const end = text.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return null;
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch {
    return null;
  }
}

/**
 * Runs the agent over one repository's recon.
 *
 * Fails into silence rather than into a wrong answer: no API key, a transport
 * error, or an unparseable response all return zero admitted hypotheses with a
 * stated reason. The caller records that reason on the run, so "the agent did
 * not run" never renders as "the agent found nothing".
 */
export async function proposeAttacks(input: AgentInput): Promise<AgentOutcome> {
  const recon: ReconIndex = {
    entries: new Set(input.routes.map((r) => r.path)),
    files: new Set(input.files),
    tables: new Set(input.tables),
    facts: new Set((input.liveFacts ?? []).map((f) => f.id)),
  };

  const interesting = input.routes.filter((r) => r.tables.length > 0);
  if (interesting.length === 0) {
    return { admitted: [], rejected: [], model: "none", skipped: true, skipReason: "no route reaches a table" };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { admitted: [], rejected: [], model: "none", skipped: true, skipReason: "no model credential configured" };
  }

  const model = interesting.length >= SONNET_ENTRY_THRESHOLD ? SONNET : HAIKU;
  const prompt = buildPrompt(input);

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model,
      max_tokens: 2000,
      system: SYSTEM,
      messages: [{ role: "user", content: prompt }],
    });

    const usage = response.usage;
    console.log(
      `[TOKENS] model=${model} input=${usage.input_tokens} output=${usage.output_tokens} cost=agent-attack`,
    );

    const text = response.content
      .map((block) => (block.type === "text" ? block.text : ""))
      .join("");

    const parsed = extractJsonArray(text);
    if (parsed === null) {
      return {
        admitted: [],
        rejected: [{ hypothesis: text.slice(0, 200), reason: "response was not JSON" }],
        model,
        skipped: false,
      };
    }

    return { ...guardHypotheses(parsed, recon), model, skipped: false };
  } catch (err) {
    return {
      admitted: [],
      rejected: [],
      model,
      skipped: true,
      skipReason: `model call failed: ${err instanceof Error ? err.message : "unknown"}`,
    };
  }
}
