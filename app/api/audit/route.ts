import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { runRepositoryAudit } from "@/lib/agent/audit";

/**
 * Starts an audit of one selected repository and returns when it is done.
 *
 * Deliberately synchronous. A queue is the right answer past a handful of
 * customers (MVP-SPEC.md §7.11) and the wrong thing to build before there are
 * any: the run already writes its progress to audit_runs, so the client can
 * poll that if the request outlives its connection.
 */
export const maxDuration = 300;

const Body = z.object({ repository: z.string().regex(/^[\w.-]+\/[\w.-]+$/) });

export async function POST(request: Request) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const parsed = Body.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Name a repository to audit." }, { status: 400 });
  }

  const admin = getSupabaseAdmin();

  const { data: profile } = await admin
    .from("user_profiles")
    .select("github_installation_id, supabase_mgmt_token_encrypted, postgres_dsn_encrypted")
    .eq("id", user.userId)
    .single();

  const installationId = profile?.github_installation_id as number | null;
  if (!installationId) {
    return NextResponse.json({ error: "Connect GitHub first." }, { status: 409 });
  }

  // The repository must already be one this account selected. Auditing an
  // arbitrary name from the body would let a caller point us at any repository
  // their installation happens to reach.
  const { data: repo } = await admin
    .from("repositories")
    .select("id, full_name")
    .eq("user_id", user.userId)
    .eq("full_name", parsed.data.repository)
    .eq("selected", true)
    .maybeSingle();

  if (!repo) {
    return NextResponse.json({ error: "That repository is not selected." }, { status: 404 });
  }

  try {
    const result = await runRepositoryAudit({
      userId: user.userId,
      installationId,
      repositoryId: repo.id as string,
      fullName: repo.full_name as string,
      trigger: "manual",
      hasDatabase: Boolean(
        profile?.supabase_mgmt_token_encrypted || profile?.postgres_dsn_encrypted,
      ),
    });

    return NextResponse.json({
      runId: result.runId,
      findings: result.findings.length,
      entries: result.entriesFound,
      tables: result.tablesFound,
      filesRead: result.filesRead,
      trace: result.trace,
      coverage: result.coverage,
    });
  } catch (err) {
    console.error("[api/audit] run failed:", err instanceof Error ? err.message : err);
    // The run row is already marked failed with its trace by runRepositoryAudit.
    // Generic message to the client (security.md); the detail is in the run.
    return NextResponse.json({ error: "The audit could not finish." }, { status: 500 });
  }
}
