import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { requestRepairAction } from "@/lib/jobs/repairAction";
import { getFixFindings } from "@/lib/fixes/findings";
import { fixLane } from "@/lib/fixes/lane";
import { hasProductAccess } from "@/lib/access";

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
  // identity, severity, title, source and approved lane are server-owned.
  const finding = (await getFixFindings(auth.user.id)).find((item) => item.id === parsed.findingId);
  if (!finding) return NextResponse.json({ error: "Finding not found." }, { status: 404 });

  // The receipt names one selected repository: the one in a repository-scoped
  // finding id, or the only selected repository. Never a guess.
  const { data: selected, error: selectedError } = await admin.from("repositories")
    .select("id, full_name").eq("user_id", auth.user.id).eq("selected", true);
  if (selectedError) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  const scoped = finding.id.includes("::") ? finding.id.slice(0, finding.id.indexOf("::")) : null;
  const rows = (selected ?? []) as { id: string; full_name: string }[];
  const repository = scoped ? rows.find((row) => row.full_name === scoped) : rows.length === 1 ? rows[0] : undefined;
  if (!repository) {
    return NextResponse.json({ error: "Choose the repository for this finding before opening a pull request." }, { status: 409 });
  }

  try {
    // A vulnerable dependency is fixed by one bump PR for its repository
    // (every bumpable package at once); anything else is a single-finding PR.
    const dependency = fixLane(finding).method === "dep-pr";
    const receiptId = await requestRepairAction(dependency
      ? { userId: auth.user.id, repositoryId: repository.id, action: "dependency-bump-pr", findingId: null, editedContent: null }
      : { userId: auth.user.id, repositoryId: repository.id, action: "finding-fix-pr",
          findingId: finding.id, editedContent: parsed.editedContent || null });
    return NextResponse.json({ receiptId, status: "queued" }, { status: 202 });
  } catch {
    return NextResponse.json({ error: "Could not queue the fix PR. Try again." }, { status: 503 });
  }
}
