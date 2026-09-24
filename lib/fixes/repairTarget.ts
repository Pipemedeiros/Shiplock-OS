import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { getFixFindings } from "@/lib/fixes/findings";
import { fixLane } from "@/lib/fixes/lane";
import type { RepairPreviewRequest } from "./preview";

/**
 * Which repair a fix button stands for, resolved from server records the way
 * each click route resolves it (Q13): the repository and lane never come from
 * the request. Null means that click route would refuse too.
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

const reviewSchema = z.object({ repository_id: z.uuid(), same_repository: z.boolean().nullable(), head_ref: z.string().nullable(),
  findings: z.array(z.object({ id: z.string() })) });

export async function resolveRepairTarget(userId: string, button: RepairButton): Promise<RepairPreviewRequest | null> {
  const admin = getSupabaseAdmin();
  if (button.lane === "pull-request") {
    const { data, error } = await admin.from("pull_request_reviews").select("repository_id, same_repository, head_ref, findings")
      .eq("id", button.reviewId).eq("user_id", userId).maybeSingle();
    if (error) throw new Error("review unreadable");
    const review = reviewSchema.safeParse(data);
    if (!review.success || !review.data.findings.some((f) => f.id === button.findingId)
      || review.data.same_repository !== true || !review.data.head_ref) return null;
    return { action: "pr-fix-pr", repositoryId: review.data.repository_id, reviewId: button.reviewId, findingId: button.findingId };
  }
  if (button.lane === "ai") {
    const { data, error } = await admin.from("intelligence_tasks").select("repository_id, status")
      .eq("id", button.taskId).eq("user_id", userId).maybeSingle();
    if (error) throw new Error("task unreadable");
    if (!data || data.status !== "proposal_received" || typeof data.repository_id !== "string") return null;
    return { action: "ai-fix-pr", repositoryId: data.repository_id, taskId: button.taskId };
  }
  if (button.lane === "risk") {
    const finding = (await getOpenFindings(userId)).find((f) => f.id === button.findingId);
    if (!finding || finding.fixKind === "manual" || finding.fixPrUrl) return null;
    const { data } = await admin.from("repositories").select("id")
      .eq("user_id", userId).eq("full_name", finding.repository ?? "").eq("selected", true).maybeSingle();
    if (!data) return null;
    return { action: "risk-fix-pr", repositoryId: data.id as string, findingId: finding.id };
  }
  const finding = (await getFixFindings(userId)).find((f) => f.id === button.findingId);
  if (!finding) return null;
  const { data: selected, error } = await admin.from("repositories").select("id, full_name").eq("user_id", userId).eq("selected", true);
  if (error) throw new Error("repositories unreadable");
  const rows = (selected ?? []) as { id: string; full_name: string }[];
  const scoped = finding.id.includes("::") ? finding.id.slice(0, finding.id.indexOf("::")) : null;
  const repository = scoped ? rows.find((row) => row.full_name === scoped) : rows.length === 1 ? rows[0] : undefined;
  if (!repository) return null;
  return fixLane(finding).method === "dep-pr"
    ? { action: "dependency-bump-pr", repositoryId: repository.id }
    : { action: "finding-fix-pr", repositoryId: repository.id, findingId: finding.id, editedContent: button.editedContent ?? null };
}
