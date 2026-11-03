import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { getFixFindings } from "@/lib/fixes/findings";
import { fixLane } from "@/lib/fixes/lane";
import type { RepairPreviewRequest } from "./preview";

/**
 * Which repair a fix button stands for, resolved from server records the way
 * each click route resolves it: the repository and lane never come from
 * the request. Every click route uses this too, so preview and click agree.
 *   pull-request  app/api/fix/pull-request (fix before merge)
 *   ai            app/api/intelligence/tasks/[id]/fix
 *   risk          app/api/fix/pr (Risks board)
 *   finding       app/api/deep/fix (fix cards; a dependency is one bump PR)
 */
export type RepairButton =
  | { lane: "pull-request"; reviewId: string; findingId: string }
  | { lane: "ai"; taskId: string }
  | { lane: "risk"; findingId: string }
  | { lane: "finding"; findingId: string; editedContent?: string | null };

export type RepairTargetResult =
  | { ok: true; target: RepairPreviewRequest }
  | { ok: false; code: "not_found" | "fork" | "no_proposal" | "manual" | "repository_unselected" | "choose_repository" }
  | { ok: false; code: "already_open"; url: string };

const reviewSchema = z.object({ repository_id: z.uuid(), same_repository: z.boolean().nullable(), head_ref: z.string().nullable(),
  findings: z.array(z.object({ id: z.string() })) });
const taskSchema = z.object({ repository_id: z.uuid(), status: z.string(), result: z.object({ edits: z.array(z.unknown()) }).nullable() });

// Findings read from the live site, fixed in the repository that serves it.
const LIVE_SITE = /^(?:exposed:|bundle:|headers:)/;

/** The selected repository the founder bound the app address to, while that
 * binding is still for the current address; otherwise the founder chooses. */
async function boundRepository(userId: string, rows: { id: string; full_name: string }[]) {
  const { data, error } = await getSupabaseAdmin().from("user_profiles")
    .select("monitored_app_url, monitored_app_bound_url, monitored_app_repository_id").eq("id", userId).maybeSingle();
  if (error) throw new Error("profile unreadable");
  const p = data as { monitored_app_url?: unknown; monitored_app_bound_url?: unknown; monitored_app_repository_id?: unknown } | null;
  if (!p || typeof p.monitored_app_url !== "string" || p.monitored_app_bound_url !== p.monitored_app_url) return undefined;
  return rows.find((row) => row.id === p.monitored_app_repository_id);
}

/** Reads throw (the caller answers 503); refusals return a code the caller
 * turns into its own message. */
export async function resolveRepairTarget(userId: string, button: RepairButton): Promise<RepairTargetResult> {
  const admin = getSupabaseAdmin();
  if (button.lane === "pull-request") {
    const { data, error } = await admin.from("pull_request_reviews").select("repository_id, same_repository, head_ref, findings")
      .eq("id", button.reviewId).eq("user_id", userId).maybeSingle();
    if (error) throw new Error("review unreadable");
    const review = reviewSchema.safeParse(data);
    if (!review.success || !review.data.findings.some((f) => f.id === button.findingId)) return { ok: false, code: "not_found" };
    if (review.data.same_repository !== true || !review.data.head_ref) return { ok: false, code: "fork" };
    return { ok: true, target: { action: "pr-fix-pr", repositoryId: review.data.repository_id, reviewId: button.reviewId, findingId: button.findingId } };
  }
  if (button.lane === "ai") {
    const { data, error } = await admin.from("intelligence_tasks").select("repository_id, status, result")
      .eq("id", button.taskId).eq("user_id", userId).maybeSingle();
    if (error) throw new Error("task unreadable");
    const task = taskSchema.safeParse(data);
    if (!task.success) return { ok: false, code: "not_found" };
    if (task.data.status !== "proposal_received" || !task.data.result?.edits.length) return { ok: false, code: "no_proposal" };
    return { ok: true, target: { action: "ai-fix-pr", repositoryId: task.data.repository_id, taskId: button.taskId } };
  }
  if (button.lane === "risk") {
    const finding = (await getOpenFindings(userId)).find((f) => f.id === button.findingId);
    if (!finding) return { ok: false, code: "not_found" };
    if (finding.fixKind === "manual") return { ok: false, code: "manual" };
    if (finding.fixPrUrl) return { ok: false, code: "already_open", url: finding.fixPrUrl };
    const { data } = await admin.from("repositories").select("id")
      .eq("user_id", userId).eq("full_name", finding.repository ?? "").eq("selected", true).maybeSingle();
    if (!data) return { ok: false, code: "repository_unselected" };
    return { ok: true, target: { action: "risk-fix-pr", repositoryId: data.id as string, findingId: finding.id } };
  }
  const finding = (await getFixFindings(userId)).find((f) => f.id === button.findingId);
  if (!finding) return { ok: false, code: "not_found" };
  const { data: selected, error } = await admin.from("repositories").select("id, full_name").eq("user_id", userId).eq("selected", true);
  if (error) throw new Error("repositories unreadable");
  const rows = (selected ?? []) as { id: string; full_name: string }[];
  const scoped = finding.id.includes("::") ? finding.id.slice(0, finding.id.indexOf("::")) : null;
  const repository = scoped ? rows.find((row) => row.full_name === scoped)
    : rows.length === 1 ? rows[0] : LIVE_SITE.test(finding.id) ? await boundRepository(userId, rows) : undefined;
  if (!repository) return { ok: false, code: "choose_repository" };
  return { ok: true, target: fixLane(finding).method === "dep-pr"
    ? { action: "dependency-bump-pr", repositoryId: repository.id }
    : { action: "finding-fix-pr", repositoryId: repository.id, findingId: finding.id, editedContent: button.editedContent ?? null } };
}
