import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runFixPr } from "@/lib/fixes/prRun";
import { FINDING_SOURCES, type FixableFinding } from "@/lib/fixes/lane";
import { hasProductAccess } from "@/lib/access";

// Opens a reviewable fix PR for one finding. Bearer auth + paid + GitHub
// connected. The PR is a new branch off the default (never merged) — a
// migration file for DB/RLS, or a fix-request file for code/logic. The customer
// reviews + merges; ShipLock never writes their DB or their default branch.
// editedContent is the user's reviewed/customized version of the fix.

const Body = z.object({
  finding: z.object({
    id: z.string().min(1).max(400),
    // Derived from lane.ts's single source of truth. Hand-listing a subset here
    // is what broke the graph/proven PR buttons: both route to real PR lanes,
    // and both 400'd on this validator.
    source: z.enum(FINDING_SOURCES),
    title: z.string().min(1).max(300),
    severity: z.enum(["CRITICAL", "WARNING", "INFO"]),
    fix: z.string().max(20_000),
    filePath: z.string().max(400).optional(),
  }),
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

  const finding: FixableFinding = parsed.finding;

  try {
    const { url } = await runFixPr(auth.user.id, finding, parsed.editedContent);
    return NextResponse.json({ url });
  } catch (err) {
    // Friendly message for the known "not connected" / "no repos" cases; generic otherwise.
    const msg = err instanceof Error && /not connected|no accessible|isn't applied/i.test(err.message)
      ? err.message
      : "Could not open the fix PR. Try again.";
    return NextResponse.json({ error: msg }, { status: 400 });
  }
}
