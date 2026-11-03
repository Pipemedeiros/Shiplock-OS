import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getIntelligenceConnection, type ConnectionView } from "./connection";

/** What the customer's own AI has and has not done. Every
 * unanswered task is pending, expired, withdrawn, or unavailable: an AI check
 * that did not run is never shown as clean. */
export type AiCheckState = "pending" | "expired" | "withdrawn" | "unavailable" | "needs_human" | "proposal";
/** What the customer's AI said, as references only: never quoted source or
 * edit bodies. It is the AI's claim, already checked against GitHub. */
type AiAnswer = { summary: string; citations: { path: string; startLine: number; endLine: number }[]; editedFiles: string[] };
export type AiCheck = {
  taskId: string; repository: string; kind: "deep" | "pr" | "other" | "audit" | "proof"; pullRequest: number | null;
  commit: string; state: AiCheckState; createdAt: string; expiresAt: string; answer: AiAnswer | null;
  /** For audit reasoning and its proof: what ShipLock's own checks made of
   * the answer, in counts. Never the agent's prose. */
  note: string | null;
};
export type AiPause = "not_connected" | "revoked" | "budget" | null;
export type AiActivity = { available: false } | { available: true; paused: AiPause; checks: AiCheck[] };

/** The state shown for one agent task. */
export function aiStateOf(status: string, expiresAt: string, now: number): AiCheckState {
  switch (status) {
    case "proposal_received": return "proposal";
    case "needs_human": return "needs_human";
    case "unavailable": return "unavailable";
    case "cancelled": return "withdrawn";
    default: return Date.parse(expiresAt) > now ? "pending" : "expired";
  }
}

/** Why agent work is paused: not connected, revoked or over budget; null when
 * running. */
export function pausedReason(connection: ConnectionView): AiPause {
  if (connection.state === "none" || connection.state === "retired") return "not_connected";
  if (connection.state === "revoked") return "revoked";
  return connection.monthReportedTokens >= connection.monthlyTokenBudget ? "budget" : null;
}

const answerSchema = z.object({
  summary: z.string(),
  citations: z.array(z.object({ path: z.string(), startLine: z.number(), endLine: z.number() })).default([]),
  edits: z.array(z.object({ path: z.string() })).default([]),
});
const taskRow = z.object({ id: z.string(), commit_sha: z.string(), status: z.string(), expires_at: z.string(),
  created_at: z.string(), idempotency_key: z.string(), repositories: z.object({ full_name: z.string() }),
  result: z.unknown().optional(), kind: z.enum(["review", "attack_reasoning", "attack_verification"]).default("review") });

const count = z.number().int().nonnegative();
const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;
/** Counts ShipLock computed when it judged an audit reasoning or proof answer. */
function noteOf(kind: z.infer<typeof taskRow>["kind"], status: string, result: unknown): string | null {
  if (status !== "proposal_received") return null;
  if (kind === "attack_reasoning") {
    const r = z.object({ admitted: z.array(z.unknown()), rejected: count }).safeParse(result);
    return r.success ? `${plural(r.data.admitted.length, "attack path", "attack paths")} passed ShipLock's checks and ${r.data.admitted.length === 1 ? "is" : "are"} being proven. ${r.data.rejected} ${r.data.rejected === 1 ? "was" : "were"} discarded.` : null;
  }
  if (kind === "attack_verification") {
    const r = z.object({ confirmed: count, refuted: count, unverified: count }).safeParse(result);
    return r.success ? `${r.data.confirmed} confirmed with quoted lines and added to Issues. ${r.data.refuted} ruled out. ${r.data.unverified} not proven.` : null;
  }
  return null;
}

function answerOf(status: string, result: unknown): AiAnswer | null {
  if (status !== "needs_human" && status !== "proposal_received") return null;
  const parsed = answerSchema.safeParse(result);
  if (!parsed.success) return null;
  return { summary: parsed.data.summary,
    citations: parsed.data.citations.map(({ path, startLine, endLine }) => ({ path, startLine, endLine })),
    editedFiles: parsed.data.edits.map((edit) => edit.path) };
}
const scanRow = z.object({ job_id: z.string(), scan: z.enum(["deep", "pr"]), pull_request_number: z.number().nullable() });
const JOB_KEY = /^job:([0-9a-f-]{36})$/;

/** The account's agent connection and its tasks from the last 30 days. */
export async function getAiActivity(userId: string, now = Date.now()): Promise<AiActivity> {
  try {
    const admin = getSupabaseAdmin();
    const [connection, tasks] = await Promise.all([
      getIntelligenceConnection(userId),
      admin.from("intelligence_tasks")
        .select("id, commit_sha, status, expires_at, created_at, idempotency_key, result, kind, repositories(full_name)")
        .eq("user_id", userId).gt("created_at", new Date(now - 30 * 86_400_000).toISOString())
        .order("created_at", { ascending: false }).limit(50),
    ]);
    if (tasks.error) return { available: false };
    const rows = z.array(taskRow).parse(tasks.data ?? []);
    // Tasks created by a scheduled scan carry their job id; look up its scope.
    const jobIds = rows.flatMap((row) => JOB_KEY.exec(row.idempotency_key)?.[1] ?? []);
    const scans = new Map<string, z.infer<typeof scanRow>>();
    if (jobIds.length > 0) {
      const read = await admin.from("intelligence_scan_jobs").select("job_id, scan, pull_request_number")
        .eq("user_id", userId).in("job_id", jobIds);
      if (read.error) return { available: false };
      for (const scan of z.array(scanRow).parse(read.data ?? [])) scans.set(scan.job_id, scan);
    }
    const checks = rows.map((row): AiCheck => {
      const scan = scans.get(JOB_KEY.exec(row.idempotency_key)?.[1] ?? "");
      const audit = row.kind !== "review";
      return { taskId: row.id, repository: row.repositories.full_name,
        kind: row.kind === "attack_reasoning" ? "audit" : row.kind === "attack_verification" ? "proof" : scan?.scan ?? "other",
        pullRequest: scan?.pull_request_number ?? null, commit: row.commit_sha,
        state: aiStateOf(row.status, row.expires_at, now), createdAt: row.created_at, expiresAt: row.expires_at,
        answer: audit ? null : answerOf(row.status, row.result), note: noteOf(row.kind, row.status, row.result) };
    });
    return { available: true, paused: pausedReason(connection), checks };
  } catch {
    return { available: false };
  }
}

/** The newest AI check on a pull request at exactly this head commit (checks
 * arrive newest first). A check of an older push is not about this code. */
export function aiCheckForPullRequest(checks: AiCheck[], repository: string, pullRequest: number, headSha: string): AiCheck | null {
  return checks.find((check) => check.kind === "pr" && check.repository === repository
    && check.pullRequest === pullRequest && check.commit === headSha) ?? null;
}
