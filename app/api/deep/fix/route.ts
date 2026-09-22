import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runFixPr } from "@/lib/fixes/prRun";
import { getFixFindings } from "@/lib/fixes/findings";
import { hasProductAccess } from "@/lib/access";

// Opens a reviewable fix PR for one finding. Bearer auth + paid + GitHub
// connected. The PR is a new branch off the default (never merged) — a
// migration file for DB/RLS, or a fix-request file for code/logic. The customer
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
