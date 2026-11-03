import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";

/** The outcome of one fix click, readable only by the account that
 * clicked. Status is queued, opened (with the PR), failed, or uncertain;
 * mergedAt is set once the customer merges it (084). */
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "Unknown request." }, { status: 400 });

  const { data, error } = await getSupabaseAdmin().from("repair_action_receipts")
    .select("status, pr_url, failure_code, merged_at").eq("id", id.data).eq("user_id", user.userId).maybeSingle();
  if (error) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  if (!data) return NextResponse.json({ error: "Unknown request." }, { status: 404 });
  return NextResponse.json(
    { status: data.status, url: data.pr_url, failure: data.failure_code, mergedAt: data.merged_at ?? null },
    { headers: { "Cache-Control": "no-store" } },
  );
}
