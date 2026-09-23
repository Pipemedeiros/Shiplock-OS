import { createHash } from "node:crypto";
import { after } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runNextRepairJob } from "./repairWorker";

export interface RepairRequest {
  userId: string;
  repositoryId: string;
  action: "risk-fix-pr" | "finding-fix-pr" | "dependency-bump-pr";
  /** Null only for a dependency bump, which covers the whole repository. */
  findingId: string | null;
  editedContent: string | null;
}

/**
 * The customer's fix click (3F-C2d). Admits one receipt plus one repair job,
 * then wakes a worker; the web request never writes to GitHub. The same
 * finding and edit within a minute share a receipt, so a double click cannot
 * open two PRs; a changed edit is a new request.
 */
export async function requestRepairAction(request: RepairRequest): Promise<string> {
  const edit = createHash("sha256").update(request.editedContent ?? "").digest("hex").slice(0, 16);
  const minute = new Date().toISOString().slice(0, 16);
  const { data, error } = await getSupabaseAdmin().rpc("request_repair_action", {
    p_user: request.userId, p_repository: request.repositoryId, p_action: request.action,
    p_finding: request.findingId, p_edited: request.editedContent,
    p_key: `${request.action}:${request.findingId ?? request.repositoryId}:${edit}:${minute}`.slice(0, 200),
  });
  const receiptId = z.uuid().safeParse(data);
  if (error || !receiptId.success) throw new Error("The fix could not be queued");
  after(async () => {
    try { await runNextRepairJob(); }
    catch (err) { console.error("[repair] queued worker stopped:", err instanceof Error ? err.message : "unknown error"); }
  });
  return receiptId.data;
}
