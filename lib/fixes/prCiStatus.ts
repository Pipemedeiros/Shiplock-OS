import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken, listPullRequestCheckRuns } from "@/lib/deep/github";
import type { OpenedPullRequest } from "./openedPullRequests";

/**
 * CI on pull requests ShipLock opened: what the customer's own
 * checks reported, read-only and bounded. ShipLock does not run CI; "none
 * visible" and "unknown" are never shown as passing.
 */
export type CiState = "passing" | "failing" | "pending" | "none_visible" | "unknown";

const PASSING = new Set(["success", "neutral", "skipped"]);

export function ciState(runs: { status: string; conclusion: string | null }[]): CiState {
  if (runs.length === 0) return "none_visible";
  if (runs.some((r) => r.status === "completed" && !PASSING.has(r.conclusion ?? ""))) return "failing";
  if (runs.some((r) => r.status !== "completed")) return "pending";
  return "passing";
}

export async function getCiStatuses(
  userId: string, prs: OpenedPullRequest[], { budgetMs = 3_000, max = 10 }: { budgetMs?: number; max?: number } = {},
): Promise<Record<string, CiState>> {
  const open = prs.filter((pr) => !pr.mergedAt);
  const result: Record<string, CiState> = Object.fromEntries(open.map((pr) => [pr.id, "unknown" as CiState]));
  if (open.length === 0) return result;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budgetMs);
  try {
    const work = (async () => {
      const { data } = await getSupabaseAdmin().from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle();
      const installationId = data?.github_installation_id as number | null | undefined;
      if (!installationId) return;
      const token = await getInstallationToken(installationId);
      await Promise.all(open.slice(0, max).map(async (pr) => {
        try {
          const runs = await listPullRequestCheckRuns(token, pr.repository, pr.number, controller.signal);
          if (!controller.signal.aborted) result[pr.id] = ciState(runs);
        } catch { /* stays unknown */ }
      }));
    })();
    const expired = new Promise<void>((resolve) => controller.signal.addEventListener("abort", () => resolve()));
    await Promise.race([work.catch(() => {}), expired]);
  } finally {
    clearTimeout(timer);
  }
  // Anything unfinished when the budget ran out stays unknown: late answers
  // are dropped above, so this object never changes after it is returned.
  return result;
}
