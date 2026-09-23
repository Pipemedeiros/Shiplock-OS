import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getIntelligenceConnection, type ConnectionView } from "./connection";

/** What the customer's own AI has and has not done (10B-2d). Every
 * unanswered task is pending, expired, withdrawn, or unavailable: an AI check
 * that did not run is never shown as clean. */
export type AiCheckState = "pending" | "expired" | "withdrawn" | "unavailable" | "needs_human" | "proposal";
export type AiCheck = {
  taskId: string; repository: string; kind: "deep" | "pr" | "other"; pullRequest: number | null;
  commit: string; state: AiCheckState; createdAt: string; expiresAt: string;
};
export type AiPause = "not_connected" | "revoked" | "budget" | null;
export type AiActivity = { available: false } | { available: true; paused: AiPause; checks: AiCheck[] };

export function aiStateOf(status: string, expiresAt: string, now: number): AiCheckState {
  switch (status) {
    case "proposal_received": return "proposal";
    case "needs_human": return "needs_human";
    case "unavailable": return "unavailable";
    case "cancelled": return "withdrawn";
    default: return Date.parse(expiresAt) > now ? "pending" : "expired";
  }
}

export function pausedReason(connection: ConnectionView): AiPause {
  if (connection.state === "none") return "not_connected";
  if (connection.state === "revoked") return "revoked";
  return connection.monthReportedTokens >= connection.monthlyTokenBudget ? "budget" : null;
}

const taskRow = z.object({ id: z.string(), commit_sha: z.string(), status: z.string(), expires_at: z.string(),
  created_at: z.string(), idempotency_key: z.string(), repositories: z.object({ full_name: z.string() }) });
const scanRow = z.object({ job_id: z.string(), scan: z.enum(["deep", "pr"]), pull_request_number: z.number().nullable() });
const JOB_KEY = /^job:([0-9a-f-]{36})$/;

export async function getAiActivity(userId: string, now = Date.now()): Promise<AiActivity> {
  try {
    const admin = getSupabaseAdmin();
    const [connection, tasks] = await Promise.all([
      getIntelligenceConnection(userId),
      admin.from("intelligence_tasks")
        .select("id, commit_sha, status, expires_at, created_at, idempotency_key, repositories(full_name)")
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
      return { taskId: row.id, repository: row.repositories.full_name, kind: scan?.scan ?? "other",
        pullRequest: scan?.pull_request_number ?? null, commit: row.commit_sha,
        state: aiStateOf(row.status, row.expires_at, now), createdAt: row.created_at, expiresAt: row.expires_at };
    });
    return { available: true, paused: pausedReason(connection), checks };
  } catch {
    return { available: false };
  }
}

/** The newest AI check on a pull request (checks arrive newest first). */
export function aiCheckForPullRequest(checks: AiCheck[], repository: string, pullRequest: number): AiCheck | null {
  return checks.find((check) => check.kind === "pr" && check.repository === repository && check.pullRequest === pullRequest) ?? null;
}
