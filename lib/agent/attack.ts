import Anthropic from "@anthropic-ai/sdk";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { guardHypotheses, type GuardResult, type ReconIndex } from "./attackGuard";
import { domainPromptLines, type DomainModel } from "./domain";
import type { PossessionGate } from "./possessionGate";
import type { StackReport } from "./stack";
import { applyVerdicts, buildVerifyPrompt, checkVerdicts, parseVerdicts, selectVerifyContext, VERIFY_SCHEMA, VERIFY_SYSTEM, type Verdict, type VerifyItem } from "./verify";

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

/**
 * The model ShipLock pays for, when it pays at all (SHIPLOCK_FUNDED_FIRST_SCAN).
 * Felipe's rule: a top-tier model, never a small one. Opus 5.5 always thinks
 * and its thinking counts toward max_tokens, so the answer budget below gets
 * THINKING_HEADROOM on top. It rejects sampling parameters: none are sent.
 */
export const PROPOSE_MODEL = "claude-opus-5-5";
export const THINKING_HEADROOM = 16_000;

// Benchmark overrides and the request each needs: Sonnet 5 rejects sampling
// parameters and thinks by default, which would spend the output budget.
const TEST_MODELS: Record<string, { thinking: { type: "disabled" } }> = {
  "claude-sonnet-5": { thinking: { type: "disabled" } },
};

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

export const SYSTEM = [
  "You are a security engineer reading an inventory of a web application.",
  "Propose where an attacker would find a way to reach data they should not.",
  "Rules: cite only routes, files, tables and live fact ids present in the input. Never invent one.",
  "Prefer authorization gaps between tenants over generic advice.",
  "Every label in this inventory is something we OBSERVED in that route's code,",
  "not a guess. Contradicting one is how a correct route gets reported as broken:",
  "  id=machine-verified: we read a shared secret or signature check, such as a",
  "    Stripe constructEvent or an HMAC comparison. Never report it as unsigned or",
  "    unauthenticated.",
  "  id=identity-unreadable: this route HAS a gate we could not follow, such as a",
  "    wrapper, a signed cookie, or an import outside what we read. NEVER report it",
  "    as public, unauthenticated or reachable by anyone. Judge it on other grounds",
  "    or leave it alone.",
  "  scope-unreadable: this route's query MAY be narrowed by the caller through a",
  "    mechanism we could not follow, such as a session lookup that carries the",
  "    scope in its arguments. NEVER report it as missing an ownership or tenant",
  "    check. Judge it on other grounds or leave it alone.",
  "  owner-filtered: we read a query narrowed by the caller's identity, such as",
  "    .eq('user_id', session.userId). Never report it as missing an ownership,",
  "    tenant or authorization check.",
  "Absence of a detail in this inventory is not evidence of a missing control, and",
  "a finding that speculates past what is listed is discarded.",
  "entry is the route path EXACTLY as listed: the text at the start of a route",
  "line, up to the first space. Never a file path, and never with the id=,",
  "scope=, methods=, tables= or file= attributes appended -- those are labels we",
  "added, not part of the path. An entry that does not match a listed path",
  "exactly is discarded along with the whole finding.",
  "citedFiles are the values after file=. citedTables are individual names from",
  "tables=, one per entry, never the comma-joined string.",
  "citedFacts refers ONLY to lines under a 'live' heading. Each such line is",
  "`<id> :: <statement>`, and the id is the text before ` :: ` -- never the",
  "statement, and never both. Omit citedFacts entirely when the input has no 'live' section:",
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
   * Milliseconds this call may take before it is abandoned.
   *
   * The audit runs inside a serverless function with a hard ceiling, and a
   * larger output budget means a longer call: raising max_tokens to cover sixty
   * findings also made it possible for the model to still be writing when the
   * function is killed. A killed function leaves the run row stuck on
   * "running" forever, which is worse than a report without attack paths.
   *
   * Omitted means no deadline, which is right for a test or a script.
   */
  timeoutMs?: number;

  /**
   * Live provider facts observed this run, as `{ id, statement }`.
   *
   * These are the half of the system that is not in the repository. They enter
   * the prompt as citable evidence and the guard checks every id the model
   * returns against this list, so a provider fact is a location in exactly the
   * way a file is.
   */
  liveFacts?: { id: string; statement: string }[];

  /**
   * Possession gates read this run (lib/agent/possessionGate.ts). Handed to the
   * guard only. buildPrompt does not read it: the model's input is unchanged,
   * and the gate changes what an admitted finding is called, not what is found.
   */
  possessionGates?: ReadonlyMap<string, PossessionGate>;

  /** Offline benchmark only (scripts/corpus.cjs paid): a model from TEST_MODELS.
   * Production never sets it, so its model choice and request are unchanged. */
  model?: string;
}

export interface AgentOutcome extends GuardResult {
  model: string;
  /** Token usage of the model response, when one arrived (Q10 cost receipts). */
  usage?: { model: string; input_tokens: number; output_tokens: number; cache_read_input_tokens: number | null; stopReason: string | null };
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
  /** A complete JSON array could not be read. Recovered objects remain guarded,
   * but the caller must disclose that reasoning coverage is incomplete. */
  parseFailed?: boolean;
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
  // Same rule as `unscoped` below, and missed for the same reason: an
  // unreadable identity ranked as anonymous, putting the routes we had just
  // decided we cannot judge at the FRONT of the sixty that reach the model.
  const anonymous = route.identityReadable && !route.authenticated && !route.machineGated;
  // An unreadable filter is not a missing one, so it must not rank as one.
  // routeRisk decides which sixty routes reach the prompt at all -- treating
  // "we could not see the scoping" as "unscoped" put exactly the routes we had
  // just decided we cannot judge at the FRONT of the queue.
  const unscoped = route.ownershipReadable && !route.ownershipFiltered;
  const touchesSensitive = route.tables.some((t) => sensitive.has(t));

  // A permission gap read from source (Step 7C): signed in and scoped, but a
  // weaker permission reaches a write another handler guards. Reportable, so
  // it enters the reasoning budget and the truncation fuse counts it.
  const permissionGap = (route.permissionGaps?.length ?? 0) > 0;

  if (anonymous && unscoped && touchesSensitive) return 0;
  if (anonymous && unscoped) return 1;
  if (route.authenticated && unscoped && touchesSensitive) return 2;
  if (route.authenticated && unscoped) return 3;
  if (anonymous) return 4;
  if (route.machineGated && unscoped) return 5;
  if (permissionGap) return 5;
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
    // "unreadable" is a fourth state, not a synonym for anonymous. The model
    // was previously handed "anonymous" for routes wrapped in withWorkspace(),
    // gated by a signed cookie, or checking an API key we did not recognise --
    // and it faithfully reasoned that anyone could call them. The label was
    // wrong, not the reasoning, so the fix is in what we hand it.
    const identity = r.machineGated
      ? "machine-verified"
      : r.authenticated
        ? "user"
        : r.identityReadable
          ? "anonymous"
          : "identity-unreadable";
    // "owner-filtered" rather than "scoped", for the same reason machine gates
    // are stated as verified: a bare adjective reads as a category the model can
    // argue with, while a stated observation is a fact it must not contradict.
    // Auditing our own repository, three correctly scoped routes were reported
    // as missing ownership checks even though the inventory said scoped, and
    // ShipLock opened pull requests against its own working code.
    // The twin of the identity label, and it was missed when that one was
    // fixed. Telling the model "unscoped" about a route whose scoping we could
    // not read is handing it the same false fact in a different column, and it
    // is the shape behind corpus-b's remaining criticals.
    const scoped = r.ownershipFiltered
      ? "owner-filtered"
      : r.ownershipReadable
        ? "unscoped"
        : "scope-unreadable";
    // THE PATH STANDS ALONE, AND NOTHING BRACKETED FOLLOWS IT.
    //
    // This line used to render as `${path} [${methods}] id=...`, and the model
    // copied `/api/feedback [ALL]` -- path plus our own bracket -- into `entry`.
    // The guard matches entries exactly, so EVERY hypothesis in the run was
    // rejected and the audit reported zero findings. Measured: in eight runs the
    // model proposed all three corpus-b true positives eight times, and five of
    // those runs were destroyed here. Whole audits, silently voided, since
    // before stage 3d.
    //
    // Methods move behind a label like every other attribute. The path is now
    // the only unlabelled token on the line, which is what makes "the text
    // before the first space" an unambiguous instruction in SYSTEM.
    return `${r.path} id=${identity} scope=${scoped} methods=${r.methods.join(",") || "GET"} tables=${r.tables.join(",")} file=${r.file}`;
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
      // ` :: ` for the same reason the route line changed: id followed by a
      // space and then prose is the shape the model absorbed on the route line,
      // and citedFacts is matched just as exactly. This one has already bitten
      // once -- 773a70c records citedFacts:["anonymous"], a label copied off a
      // route line -- so it gets a delimiter that cannot occur inside an id.
      ? ["live", ...input.liveFacts.slice(0, 20).map((f) => `${f.id} :: ${f.statement}`)]
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

/**
 * THE TRUNCATION FUSE.
 *
 * Coverage tells the customer that the routes left out of the prompt "are the
 * ones already scoped or already guarded". That is true only while every route
 * of a reportable shape fits inside MAX_PROMPT_ROUTES, and it is true today
 * only by margin: measured 2026-09-08, corpus-a has 54 routes in risk bands 0-5
 * against a cap of 60, corpus-b 20, corpus-c 3. Seven more anonymous or
 * unscoped routes in corpus-a and real candidates start being dropped -- silently,
 * with an output indistinguishable from a clean scan, under a Coverage note
 * still saying the dropped ones were safe.
 *
 * `routeRisk` puts every reportable shape in bands 0-5 and authenticated-and-
 * scoped in band 6, so "a route we would have reported got cut" is exactly
 * "something below the cap scored under 6". `sensitive` only separates bands
 * 0/1 and 2/3, never the 5/6 boundary, so it is not needed here.
 *
 * Returns 0 in the healthy case, which is the case on every corpus repository
 * today. Any non-zero means the cap is now hiding candidates.
 */
export function riskyRoutesOmitted(input: AgentInput): number {
  const interesting = input.routes.filter((r) => r.tables.length > 0);
  if (interesting.length <= MAX_PROMPT_ROUTES) return 0;
  const cut = rankRoutes(interesting, new Set(input.domain?.sensitive ?? [])).slice(MAX_PROMPT_ROUTES);
  return cut.filter((r) => routeRisk(r, new Set()) < 6).length;
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
    routes: new Map(input.routes.map((r) => [r.path, r])),
    possessionGates: input.possessionGates,
  };

  const interesting = input.routes.filter((r) => r.tables.length > 0);
  if (interesting.length === 0) {
    return { admitted: [], rejected: [], unassessed: [], unmatchedEntries: [], model: "none", skipped: true, skipReason: "no route reaches a table" };
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return { admitted: [], rejected: [], unassessed: [], unmatchedEntries: [], model: "none", skipped: true, skipReason: "no model credential configured" };
  }

  if (input.model !== undefined && !TEST_MODELS[input.model]) {
    throw new Error(`${input.model} is not an allowed test model`);
  }
  const model = input.model ?? PROPOSE_MODEL;
  const prompt = buildPrompt(input);

  try {
    const client = new Anthropic({ apiKey });
    const response = await client.messages.create({
      model,
      max_tokens: maxTokensFor(interesting.length) + (input.model ? 0 : THINKING_HEADROOM),
      // 5.5 models take no sampling parameters and always think; the output is
      // probabilistic, so consistency comes from the guard and the verifier
      // (verify.ts), which admit only what the code proves.
      ...(input.model ? TEST_MODELS[input.model] : { output_config: { effort: "medium" as const } }),
      system: SYSTEM,
      messages: [{ role: "user", content: prompt }],
    }, input.timeoutMs ? { timeout: input.timeoutMs } : undefined);

    const usage = response.usage;
    const receipt = { model, input_tokens: usage.input_tokens, output_tokens: usage.output_tokens,
      cache_read_input_tokens: usage.cache_read_input_tokens ?? null, stopReason: response.stop_reason ?? null };
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
    const parseFailed = parsed === null && !truncated;

    if (!Array.isArray(hypotheses) || (hypotheses.length === 0 && parsed === null)) {
      return {
        admitted: [],
        rejected: [{ hypothesis: text.slice(0, 200), reason: truncated ? "response was cut off before any finding was complete" : "response was not JSON" }],
        unassessed: [],
        unmatchedEntries: [],
        model,
        skipped: false,
        truncated,
        parseFailed,
        usage: receipt,
      };
    }

    return { ...guardHypotheses(hypotheses, recon), model, skipped: false, truncated, parseFailed, usage: receipt };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    const timedOut = err instanceof Anthropic.APIConnectionTimeoutError || /timeout/i.test(message);
    return {
      admitted: [],
      rejected: [],
      unassessed: [],
      unmatchedEntries: [],
      model,
      skipped: true,
      skipReason: timedOut
        ? "reasoning did not finish inside this run's time budget"
        : `model call failed: ${message}`,
    };
  }
}

type VerifyProposal = { entry: string; attackClass: string; title: string; consequence: string; citedFiles?: string[] };

/** P1: the verifier model. A 5.5-generation model (Felipe: never a small one). */
export const VERIFY_MODEL = "claude-sonnet-5-5";
const VERIFY_MAX_TOKENS = 16_000;
/** Claims per verifier call, so each verdict keeps room to cite its lines. */
export const VERIFY_BATCH = 10;

export interface VerifyOutcome {
  verdicts: Verdict[];
  shown: string[];
  omitted: string[];
  model: string;
  skipped: boolean;
  skipReason?: string;
  usage?: { model: string; input_tokens: number; output_tokens: number; cache_read_input_tokens: number | null; stopReason: string | null };
}

/**
 * Second pass over admitted hypotheses (see verify.ts). Same funding rule as
 * proposeAttacks: it runs only inside a run that already holds the first-scan
 * credit, on ShipLock's key. A failure verifies nothing; every claim is then
 * unverified, which keeps it out of the findings.
 */
export async function verifyAttacks(input: { items: VerifyItem[]; files: ReadonlyMap<string, string>; timeoutMs?: number; model?: string;
  maxTokens?: number; budgetChars?: number }): Promise<VerifyOutcome> {
  const context = selectVerifyContext(input.items, input.files, input.budgetChars);
  const unverifiedAll = (reason: string): Verdict[] => input.items.map((item) =>
    ({ id: item.id, verdict: "unverified", severity: "medium", statement: "", reason, citations: [], citationProblem: "not run" }));
  const model = input.model ?? VERIFY_MODEL;
  if (input.items.length === 0) return { verdicts: [], ...context, model: "none", skipped: true, skipReason: "nothing to verify" };
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return { verdicts: unverifiedAll("no model credential configured"), ...context, model: "none", skipped: true, skipReason: "no model credential configured" };
  try {
    const client = new Anthropic({ apiKey, maxRetries: 0 });
    const response = await client.messages.create({
      model,
      max_tokens: input.maxTokens ?? VERIFY_MAX_TOKENS,
      output_config: { effort: "high", format: { type: "json_schema", schema: VERIFY_SCHEMA as unknown as Record<string, unknown> } },
      system: VERIFY_SYSTEM,
      messages: [{ role: "user", content: buildVerifyPrompt(input.items, input.files, context) }],
    }, input.timeoutMs ? { timeout: input.timeoutMs } : undefined);
    const usage = { model, input_tokens: response.usage.input_tokens, output_tokens: response.usage.output_tokens,
      cache_read_input_tokens: response.usage.cache_read_input_tokens ?? null, stopReason: response.stop_reason ?? null };
    const text = response.content.map((block) => (block.type === "text" ? block.text : "")).join("");
    const raw = response.stop_reason === "refusal" ? null : parseVerdicts(text);
    if (!raw) return { verdicts: unverifiedAll("the verifier's answer could not be read"), ...context, model, skipped: false, usage };
    return { verdicts: checkVerdicts(raw, input.items, input.files, new Set(context.shown)), ...context, model, skipped: false, usage };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown";
    return { verdicts: unverifiedAll(`verification call failed: ${message}`), ...context, model, skipped: true, skipReason: message };
  }
}

/**
 * The audit's use of the verifier: every admitted proposal is checked in
 * batches; only confirmed ones are kept. `failed` says a call did not return,
 * so the run's coverage marks verification incomplete.
 */
export async function verifyAdmitted<H extends VerifyProposal>(input: { admitted: H[]; routes: { path: string; file: string }[];
  files: ReadonlyMap<string, string>; timeoutMs?: number }): Promise<{ kept: H[]; refuted: number; unverified: number; failed: boolean;
  usages: NonNullable<VerifyOutcome["usage"]>[] }> {
  const items: VerifyItem[] = input.admitted.map((h, i) => ({ id: String(i), entry: h.entry, attackClass: h.attackClass, title: h.title,
    consequence: h.consequence, citedFiles: h.citedFiles ?? [], handlerFile: input.routes.find((r) => r.path === h.entry)?.file }));
  const verdicts: Verdict[] = [];
  const usages: NonNullable<VerifyOutcome["usage"]>[] = [];
  let failed = false;
  for (let i = 0; i < items.length; i += VERIFY_BATCH) {
    const outcome = await verifyAttacks({ items: items.slice(i, i + VERIFY_BATCH), files: input.files, timeoutMs: input.timeoutMs });
    if (outcome.usage) usages.push(outcome.usage);
    if (outcome.skipped) failed = true;
    verdicts.push(...outcome.verdicts);
  }
  return { ...applyVerdicts(input.admitted, verdicts), failed, usages };
}
