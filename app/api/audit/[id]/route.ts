import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";

/** One run, for polling while it is in flight and for reading it back later. */
export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const { id } = await context.params;
  const admin = getSupabaseAdmin();

  // Scoped to the caller: a run id is a uuid, but an id being unguessable is
  // not an authorization check.
  const { data: run } = await admin
    .from("audit_runs")
    .select("id, full_name, status, trace, coverage, findings_count, entries_found, tables_found, files_read, started_at, finished_at, error")
    .eq("id", id)
    .eq("user_id", user.userId)
    .maybeSingle();

  if (!run) return NextResponse.json({ error: "No such run." }, { status: 404 });
  return NextResponse.json(run);
}
