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
  "Rules: cite only routes, files and tables present in the input. Never invent one.",
  "Prefer authorization gaps between tenants over generic advice.",
  "Ignore anything already gated by a machine secret or signature.",
  "Return JSON only: an array of",
  '{entry, attackClass, title, consequence, citedFiles[], citedTables[]}.',
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
export function buildPrompt(input: AgentInput): string {
  const interesting = input.routes.filter((r) => r.tables.length > 0);

  const routeLines = interesting.slice(0, 60).map((r) => {
    const identity = r.machineGated ? "machine" : r.authenticated ? "user" : "anonymous";
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
    "routes",
    ...routeLines,
  ].join("\n");
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
