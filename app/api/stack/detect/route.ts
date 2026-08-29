import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken } from "@/lib/deep/github";
import { fetchRepoArchive } from "@/lib/deep/repoArchive";
import { detectStack } from "@/lib/agent/stack";

/**
 * Reads one selected repository and reports the stack it declares.
 *
 * Onboarding needs this before the audit runs, because the stack step is what
 * the customer sees between choosing repositories and waiting several minutes.
 * It is the same read the audit performs, run on its own so the screen has
 * something true to show without waiting for the whole pipeline.
 *
 * Nothing is persisted here. The audit stores the stack it reasoned over, and
 * two writers of the same row would let a fast screen overwrite the record of
 * what an audit actually used.
 */
export const maxDuration = 60;

const Body = z.object({ repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/) });

export async function POST(request: Request) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Name a repository to read." }, { status: 400 });
  }

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", user.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId) {
    return NextResponse.json({ error: "Connect GitHub first." }, { status: 409 });
  }

  // Same rule as the audit route: the repository must be one this account
  // selected. Reading an arbitrary name from the body would let a caller point
  // us at anything their installation happens to reach.
  const { data: repo } = await admin
    .from("repositories")
    .select("id")
    .eq("user_id", user.userId)
    .eq("full_name", parsed.data.repository)
    .eq("selected", true)
    .maybeSingle();

  if (!repo) {
    return NextResponse.json({ error: "That repository is not selected." }, { status: 404 });
  }

  try {
    const token = await getInstallationToken(installationId);
    const archive = await fetchRepoArchive(token, parsed.data.repository);
    const stack = detectStack(archive.files);

    return NextResponse.json({
      tools: stack.tools.map((t) => ({
        id: t.id,
        name: t.name,
        kind: t.kind,
        evidence: t.evidence,
      })),
      authUnknown: stack.authUnknown,
      databaseUnknown: stack.databaseUnknown,
      filesRead: archive.files.length,
    });
  } catch (err) {
    console.error("[api/stack/detect] failed:", err instanceof Error ? err.message : err);
    return NextResponse.json({ error: "Could not read the repository." }, { status: 502 });
  }
}
