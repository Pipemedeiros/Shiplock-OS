import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runReasoningPass } from "@/lib/deep/reasoningRun";

// Layer 3 — the reasoning pass over the connected GitHub repo. Pro-gated. One
// cheap Haiku call reasons over a deterministic map of endpoints + RPCs and
// writes source='github-reasoned' findings (framed as reasoned, not proven).
export async function POST() {
  const pro = await requireProUser();
  if (!pro) {
    return NextResponse.json({ error: "Authentication required." }, { status: 403 });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", pro.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null | undefined;
  if (!installationId) {
    return NextResponse.json({ error: "GitHub is not connected." }, { status: 400 });
  }

  try {
    const { total, newCount } = await runReasoningPass(pro.userId, installationId);
    return NextResponse.json({ ok: true, total, newCount }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Reasoning pass failed. Try again." }, { status: 502 });
  }
}
