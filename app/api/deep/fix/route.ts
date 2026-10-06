import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { hasProductAccess } from "@/lib/access";
import { quotaResponse } from "@/lib/quota";
import { bearerMfaOk } from "@/lib/mfa";

// The customer's click to open a reviewable fix PR for one finding. Admits a
// receipted repair job (3F-C2d); the worker opens a new branch off the default
// (never merged) with a migration, codemod, or fix-request file. The customer
// reviews + merges; ShipLock never writes their DB or their default branch.
// editedContent is the user's reviewed/customized version of the fix.

const Body = z.object({
  findingId: z.string().min(1).max(400),
  editedContent: z.string().max(60_000),
});

export async function POST(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) return NextResponse.json({ error: "Authentication required." }, { status: 401 });

  const admin = getSupabaseAdmin();
  const { data: auth } = await admin.auth.getUser(token);
  if (!auth.user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (!bearerMfaOk(auth.user, token)) return NextResponse.json({ error: "Enter the code from your authenticator app first." }, { status: 403 });

  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid")
    .eq("id", auth.user.id)
    .maybeSingle();
  if (!profile || !hasProductAccess(profile)) return NextResponse.json({ error: "A subscription is required." }, { status: 402 });

  let parsed;
  try {
    parsed = Body.parse(await req.json());
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  // Only the customer's edited artifact comes from the request. Finding
  // identity, lane and repository are resolved from our records, exactly as
  // the preview resolves them (Q13-F).
  let resolved;
  try {
    resolved = await resolveRepairTarget(auth.user.id, { lane: "finding", findingId: parsed.findingId, editedContent: parsed.editedContent || null });
  } catch {
    return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  }
  if (!resolved.ok) {
    if (resolved.code === "not_found") return NextResponse.json({ error: "Finding not found." }, { status: 404 });
    return NextResponse.json({ error: "Choose the repository for this finding before opening a pull request." }, { status: 409 });
  }
  const { target } = resolved;

  try {
    // A vulnerable dependency is fixed by one bump PR for its repository
    // (every bumpable package at once); anything else is a single-finding PR.
    const receiptId = await requestRepairAction(target.action === "dependency-bump-pr"
      ? { userId: auth.user.id, repositoryId: target.repositoryId, action: "dependency-bump-pr", findingId: null, editedContent: null }
      : { userId: auth.user.id, repositoryId: target.repositoryId, action: "finding-fix-pr",
          findingId: target.findingId!, editedContent: target.editedContent ?? null });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch (err) {
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the fix PR. Try again." }, { status: 503 });
  }
}
