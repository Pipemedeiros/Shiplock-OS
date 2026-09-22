import { after, NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { enqueueJob } from "@/lib/jobs/queue";
import { runNextJob } from "@/lib/jobs/worker";

// Admit a re-scan for every selected repository. The request never performs
// provider I/O or writes evidence; a leased worker owns both.
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
    const { data: repositories, error } = await admin
      .from("repositories")
      .select("id")
      .eq("user_id", pro.userId)
      .eq("selected", true)
      .limit(50);
    if (error) throw new Error("selection unavailable");
    const hour = new Date().toISOString().slice(0, 13);
    for (const repository of repositories ?? []) {
      await enqueueJob(
        pro.userId,
        repository.id as string,
        "source",
        `manual-source:${repository.id}:${hour}`,
      );
    }
    if ((repositories ?? []).length > 0) {
      after(async () => {
        await runNextJob().catch(() => {});
      });
    }
    return NextResponse.json(
      { ok: true, queued: (repositories ?? []).length },
      { status: 202, headers: { "Cache-Control": "no-store" } },
    );
  } catch {
    return NextResponse.json({ error: "Scan could not be queued. Try again." }, { status: 503 });
  }
}
