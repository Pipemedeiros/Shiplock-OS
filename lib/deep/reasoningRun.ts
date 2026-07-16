import Anthropic from "@anthropic-ai/sdk";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { Severity } from "@/lib/types";
import { getInstallationToken, listRepos, listTree, getFile } from "./github";
import type { RepoFile } from "./githubScan";
import { buildReasoningContext, isRouteFile, type ReasoningContext } from "./reasoningContext";
import { REASONING_SYSTEM_PROMPT, buildReasoningUserPrompt } from "./reasoningPrompt";

// Layer 3 orchestration — a single cheap Haiku call reasoning over the
// deterministic map. Runs on Vercel (just an API call; no Docker). Findings are
// persisted as source='github-reasoned' and framed honestly as reasoned, never
// proven. Model routing + token logging follow the analyzer doctrine (Haiku).
const MODEL = "claude-haiku-4-5-20251001";
const TIMEOUT_MS = 30_000;
const MAX_REPOS = 5;
const MAX_FILES_PER_REPO = 60;
const MAX_FILE_BYTES = 200_000;

export interface ReasonedFinding {
  title: string;
  severity: Severity;
  consequence: string;
  location: string;
  confidence: "high" | "medium" | "low";
  why: string;
}

const SEVERITIES = new Set(["CRITICAL", "WARNING", "INFO"]);
const CONFIDENCES = new Set(["high", "medium", "low"]);

// PURE: parse + validate the LLM JSON. Drops malformed items rather than throwing.
export function parseReasonedFindings(rawText: string): ReasonedFinding[] {
  const raw = rawText.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  const arr = (parsed as { findings?: unknown })?.findings;
  if (!Array.isArray(arr)) return [];
  const out: ReasonedFinding[] = [];
  for (const item of arr) {
    const i = item as Record<string, unknown>;
    if (
      typeof i.title !== "string" ||
      typeof i.consequence !== "string" ||
      typeof i.location !== "string" ||
      typeof i.why !== "string" ||
      !SEVERITIES.has(i.severity as string) ||
      !CONFIDENCES.has(i.confidence as string)
    ) {
      continue;
    }
    out.push({
      title: i.title,
      severity: i.severity as Severity,
      consequence: i.consequence,
      location: i.location,
      confidence: i.confidence as ReasonedFinding["confidence"],
      why: i.why,
    });
  }
  return out;
}

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60);

export interface DeepFindingRow {
  finding_id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

// PURE: normalize reasoned findings into deep_findings rows with the honest
// "reasoned, not proven" framing baked into the copy.
export function toDeepFindingRows(findings: ReasonedFinding[]): DeepFindingRow[] {
  return findings.map((f) => ({
    finding_id: `github-reasoned:${f.confidence}:${slug(f.location)}:${slug(f.title)}`,
    severity: f.severity,
    title: `Likely: ${f.title}`,
    consequence:
      `${f.consequence} Reasoned from your code — not confirmed by an exploit (confidence: ${f.confidence}). ` +
      `Where to check: ${f.location}. ${f.why}`,
  }));
}

// Network: the single Haiku reasoning call. Returns [] on any failure (fail-soft).
export async function reasonOverContext(ctx: ReasoningContext): Promise<ReasonedFinding[]> {
  if (ctx.endpoints.length === 0 && ctx.rpcs.length === 0) return [];
  const client = new Anthropic();
  try {
    const res = await client.messages.create(
      {
        model: MODEL,
        max_tokens: 2500,
        system: REASONING_SYSTEM_PROMPT,
        messages: [{ role: "user", content: buildReasoningUserPrompt(ctx) }],
      },
      { timeout: TIMEOUT_MS, maxRetries: 0 }
    );
    console.log(`[reasoning] model=${MODEL} input_tokens=${res.usage.input_tokens} output_tokens=${res.usage.output_tokens}`);
    const text = res.content.find((b) => b.type === "text");
    return text && text.type === "text" ? parseReasonedFindings(text.text) : [];
  } catch (err) {
    console.error("[reasoning] Anthropic call failed:", err instanceof Error ? err.message : err);
    return [];
  }
}

async function fetchContextFiles(token: string, fullName: string, branch: string): Promise<RepoFile[]> {
  const tree = await listTree(token, fullName, branch);
  const candidates = tree
    .filter((t) => t.size <= MAX_FILE_BYTES && (isRouteFile(t.path) || /\.sql$/i.test(t.path)))
    .slice(0, MAX_FILES_PER_REPO);
  const files: RepoFile[] = [];
  for (const c of candidates) {
    const content = await getFile(token, fullName, c.path, branch).catch(() => null);
    if (content != null) files.push({ path: c.path, content });
  }
  return files;
}

export async function runReasoningPass(
  userId: string,
  installationId: string | number
): Promise<{ total: number; newCount: number }> {
  const admin = getSupabaseAdmin();
  const token = await getInstallationToken(installationId);
  const repos = (await listRepos(token)).slice(0, MAX_REPOS);

  const rows: DeepFindingRow[] = [];
  for (const repo of repos) {
    try {
      const files = await fetchContextFiles(token, repo.fullName, repo.defaultBranch);
      const findings = await reasonOverContext(buildReasoningContext(files));
      // namespace by repo so the same reasoned issue in two repos stays distinct
      rows.push(...toDeepFindingRows(findings).map((r) => ({ ...r, finding_id: `${repo.fullName}::${r.finding_id}` })));
    } catch {
      continue;
    }
  }

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "github-reasoned")
    .is("archived_at", null);
  const activeIds = new Set((existing ?? []).map((r) => r.finding_id as string));

  const fresh = rows.filter((r) => !activeIds.has(r.finding_id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((r) => ({
        user_id: userId, source: "github-reasoned", finding_id: r.finding_id,
        severity: r.severity, title: r.title, consequence: r.consequence,
        package_name: null, version: null, vuln_id: null, cve_id: null,
      }))
    );
  }
  return { total: rows.length, newCount: fresh.length };
}
