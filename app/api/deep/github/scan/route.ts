import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runGithubScan } from "@/lib/deep/githubRun";

// Run (or re-run) the GitHub source scan for the caller's connected
// installation. Pro-gated server-side. Persists only new deep_findings.
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
    const { total, newCount } = await runGithubScan(pro.userId, installationId);
    return NextResponse.json({ ok: true, total, newCount }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Scan failed. Try again." }, { status: 502 });
  }
}
