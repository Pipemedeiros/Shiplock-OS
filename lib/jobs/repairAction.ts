import { createHash } from "node:crypto";
import { after } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runNextRepairJob } from "./repairWorker";
import { quotaCode } from "@/lib/quota";

export interface RepairRequest {
  userId: string;
  repositoryId: string;
  action: "risk-fix-pr" | "finding-fix-pr" | "dependency-bump-pr" | "pr-fix-pr" | "ai-fix-pr" | "rate-limit-pr";
  /** Null only for a dependency bump, which covers the whole repository. */
  findingId: string | null;
  editedContent: string | null;
  /** Required for pr-fix-pr: the stored review whose head branch the fix targets. */
  reviewId?: string;
  /** Required for ai-fix-pr: the answered intelligence task whose edits the PR carries. */
  taskId?: string;
}

/**
 * The customer's fix click (3F-C2d). Admits one receipt plus one repair job,
 * then wakes a worker; the web request never writes to GitHub. The same
 * finding and edit within a minute share a receipt, so a double click cannot
 * open two PRs; a changed edit is a new request.
 */
export async function requestRepairAction(request: RepairRequest): Promise<string> {
  const { data, error } = await getSupabaseAdmin().rpc("request_repair_action", {
    p_user: request.userId, p_repository: request.repositoryId, p_action: request.action,
    p_finding: request.findingId, p_edited: request.editedContent, p_review: request.reviewId ?? null,
    p_task: request.taskId ?? null, p_key: repairKey(request),
  });
  return admitted(data, error);
}

/** Thrown when the customer has not let their agent open pull requests. */
export const AGENT_PRS_OFF = "agent_prs_off";

/**
 * The customer's own agent asking for the same fix PR a click would open
 * (103, Felipe 2026-10-15). Refused unless the customer turned agent pull
 * requests on for this repository in the dashboard; otherwise exactly the
 * click's queue, cap and key, with the grant named on the receipt.
 */
export async function requestAgentRepairAction(request: { userId: string; repositoryId: string; findingId: string }): Promise<string> {
  const { data, error } = await getSupabaseAdmin().rpc("request_agent_repair_action", {
    p_user: request.userId, p_repository: request.repositoryId, p_finding: request.findingId,
    p_key: repairKey({ action: "risk-fix-pr", findingId: request.findingId, repositoryId: request.repositoryId, editedContent: null }),
  });
  if (error && /agent pull requests off/.test(error.message)) throw new Error(AGENT_PRS_OFF);
  return admitted(data, error);
}

function repairKey(request: Pick<RepairRequest, "action" | "findingId" | "repositoryId" | "editedContent">): string {
  const edit = createHash("sha256").update(request.editedContent ?? "").digest("hex").slice(0, 16);
  const minute = new Date().toISOString().slice(0, 16);
  return `${request.action}:${request.findingId ?? request.repositoryId}:${edit}:${minute}`.slice(0, 200);
}

function admitted(data: unknown, error: { message: string } | null): string {
  const receiptId = z.uuid().safeParse(data);
  if (error) throw new Error(quotaCode(error.message) ?? "The fix could not be queued");
  if (!receiptId.success) throw new Error("The fix could not be queued");
  after(async () => {
    try { await runNextRepairJob(); }
    catch (err) { console.error("[repair] queued worker stopped:", err instanceof Error ? err.message : "unknown error"); }
  });
  return receiptId.data;
}
