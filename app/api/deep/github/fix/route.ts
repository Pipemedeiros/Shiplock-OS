import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runGithubFix } from "@/lib/deep/githubFixRun";

// Open dependency-bump fix PRs for the caller's connected installation.
// Pro-gated server-side. Opens reviewable PRs on a new branch only — never
// pushes to the default branch, never merges, never edits app/DB/auth code.
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
    const { prs, repos } = await runGithubFix(pro.userId, installationId);
    return NextResponse.json({ ok: true, prs, repos }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Could not open fix PRs. Try again." }, { status: 502 });
  }
}
