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

/**
 * Output budget, sized to the answer we asked for rather than to a round number.
 *
 * The old value was a flat 2000, which is roughly nine findings once each
 * carries a title, a consequence and its citations. Every audit of a real
 * startup codebase overflowed it, and overflow silently produced a CLEAN
 * REPORT. Sixty routes is what MAX_PROMPT_ROUTES lets into the prompt, and a
 * finding runs about 220 output tokens, so the ceiling is what it would cost to
 * report on everything we asked about.
 */
export function maxTokensFor(interestingEntries: number): number {
  const perFinding = 220;
  const askedAbout = Math.min(interestingEntries, MAX_PROMPT_ROUTES);
  return Math.min(16000, Math.max(4000, Math.ceil(askedAbout * perFinding)));
}

const SYSTEM = [
  "You are a security engineer reading an inventory of a web application.",
  "Propose where an attacker would find a way to reach data they should not.",
  "Rules: cite only routes, files, tables and live fact ids present in the input. Never invent one.",
  "Prefer authorization gaps between tenants over generic advice.",
  "Every label in this inventory is something we OBSERVED in that route's code,",
  "not a guess. Contradicting one is how a correct route gets reported as broken:",
  "  id=machine-verified: we read a shared secret or signature check, such as a",
  "    Stripe constructEvent or an HMAC comparison. Never report it as unsigned or",
  "    unauthenticated.",
  "  owner-filtered: we read a query narrowed by the caller's identity, such as",
  "    .eq('user_id', session.userId). Never report it as missing an ownership,",
  "    tenant or authorization check.",
  "Absence of a detail in this inventory is not evidence of a missing control, and",
  "a finding that speculates past what is listed is discarded.",
  "entry is the route path exactly as listed under 'routes', never a file path.",
  "citedFacts refers ONLY to lines under a 'live' heading, each of which starts",
  "with its id. Omit citedFacts entirely when the input has no 'live' section:",
  "an id we did not give you is discarded along with the whole finding. Only a",
  "finding with no route at all, such as a leaked credential, uses such an id as",
  "its entry. Copy routes and ids exactly; a reworded one is discarded.",
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
  /**
   * The model ran out of output budget mid-answer.
   *
   * Load-bearing rather than diagnostic: a truncated run has looked at only
   * part of what it was asked about, so "no attack paths" from it is not a
   * clean bill of health. The caller MUST surface this on the Coverage page,
   * for the same reason a skipped reasoning step is surfaced there.
   */
  truncated?: boolean;
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
    // "owner-filtered" rather than "scoped", for the same reason machine gates
    // are stated as verified: a bare adjective reads as a category the model can
    // argue with, while a stated observation is a fact it must not contradict.
    // Auditing our own repository, three correctly scoped routes were reported
    // as missing ownership checks even though the inventory said scoped, and
    // ShipLock opened pull requests against its own working code.
    const scoped = r.ownershipFiltered ? "owner-filtered" : "unscoped";
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
 * Every COMPLETE object in a possibly-truncated JSON array.
 *
 * Measured on a real 234k-line repository: every single reasoning call came
 * back with stop_reason "max_tokens", the array cut off mid-object, and
 * extractJsonArray returned null because there was no closing bracket. The
 * whole run was then reported as "response was not JSON" and the customer got
 * ZERO findings from a model that had just written nine of them.
 *
 * That is the bimodality behind 0, 13, 12, 0, 0, 10, 2, 10, 9, 7 admitted
 * hypotheses across ten runs of one repository: not the model changing its
 * mind, but whether its answer happened to fit in the budget. A run that
 * overflowed threw away everything; a run that fitted kept everything.
 *
 * Objects that ARE complete were paid for and are as valid as any other -- the
 * guard still judges each one. Only the object the cut lands inside is lost.
 */
export function salvageJsonObjects(text: string): unknown[] {
  const start = text.indexOf("[");
  if (start === -1) return [];

  const out: unknown[] = [];
  let depth = 0;
  let objectStart = -1;
  let inString = false;
  let escaped = false;

  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }

    if (ch === '"') { inString = true; continue; }
    if (ch === "{") { if (depth === 0) objectStart = i; depth++; continue; }
    if (ch === "}") {
      depth--;
      if (depth === 0 && objectStart !== -1) {
        try {
          out.push(JSON.parse(text.slice(objectStart, i + 1)));
        } catch {
          // A complete-looking object that will not parse is dropped, not fatal.
        }
        objectStart = -1;
      }
      continue;
    }
    // The array's own closing bracket at depth 0 ends the scan.
    if (ch === "]" && depth === 0) break;
  }

  return out;
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
      max_tokens: maxTokensFor(interesting.length),
      // Deterministic decoding. This is an extraction task with a fixed output
      // schema, not a creative one, and two audits of an unchanged repository
      // that disagree are two audits the customer cannot trust. Sampling bought
      // nothing here and cost reproducibility.
      temperature: 0,
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

    const truncated = response.stop_reason === "max_tokens";

    // A complete answer parses whole. A truncated one is salvaged object by
    // object rather than discarded: the findings the model finished writing
    // were paid for and are still judged by the guard.
    const parsed = extractJsonArray(text);
    const hypotheses = parsed !== null ? parsed : salvageJsonObjects(text);

    if (!Array.isArray(hypotheses) || hypotheses.length === 0) {
      return {
        admitted: [],
        rejected: [{ hypothesis: text.slice(0, 200), reason: truncated ? "response was cut off before any finding was complete" : "response was not JSON" }],
        model,
        skipped: false,
        truncated,
      };
    }

    return { ...guardHypotheses(hypotheses, recon), model, skipped: false, truncated };
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
