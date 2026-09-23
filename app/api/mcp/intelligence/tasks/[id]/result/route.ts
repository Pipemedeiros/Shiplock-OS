import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { submitIntelligenceResult } from "@/lib/intelligence/tasks";

// Refusal codes a host can act on; anything else is reported generically.
const STATUS: Record<string, number> = {
  invalid_result: 422, result_too_large: 413, scope_mismatch: 422, source_not_allowed: 422,
  citation_mismatch: 422, missing_evidence: 422, missing_patch: 422, invalid_unavailable: 422,
  human_decision_required: 422, edit_not_allowed: 422, source_changed: 409, source_unreadable: 503,
  task_expired: 409, task_scope_changed: 409, already_completed: 409, task_unavailable: 404,
};

/** A customer's host submits one result for its own task (10B-1b). ShipLock
 * verifies the evidence against GitHub and stores a proposal only; it never
 * applies an edit, opens a PR, or treats reported usage as verified. */
export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await authMcp(req);
  if ("error" in auth) return auth.error;
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "invalid_task" }, { status: 400 });
  const body = await req.json().catch(() => null) as { result?: unknown } | null;
  if (!body || typeof body !== "object" || !("result" in body)) {
    return NextResponse.json({ error: "invalid_result" }, { status: 422 });
  }
  try {
    const receipt = await submitIntelligenceResult(auth.userId, id.data, body.result);
    return NextResponse.json(receipt, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    const code = err instanceof Error && err.message in STATUS ? err.message : "submission_failed";
    return NextResponse.json({ error: code }, { status: STATUS[code] ?? 500 });
  }
}
