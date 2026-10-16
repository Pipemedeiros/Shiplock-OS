import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { getSupabaseAdmin } from "@/lib/supabase";

/** MCP tool `get_fix_pull_request`: the outcome of a fix PR request, for the
 * token owner only. Same answer as the dashboard's /api/fix/receipts/[id]. */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "Unknown request." }, { status: 400 });

  const { data, error } = await getSupabaseAdmin().from("repair_action_receipts")
    .select("status, pr_url, failure_code, merged_at").eq("id", id.data).eq("user_id", ctx.userId).maybeSingle();
  if (error) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  if (!data) return NextResponse.json({ error: "Unknown request." }, { status: 404 });
  return NextResponse.json(
    { status: data.status, url: data.pr_url, failure: data.failure_code, mergedAt: data.merged_at ?? null },
    { headers: { "Cache-Control": "no-store" } },
  );
}
