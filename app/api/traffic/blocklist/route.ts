import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getActiveBlocklist } from "@/lib/traffic/blocklist";

// Serves the active blocklist to the customer's middleware snippet. Same
// per-site token auth (`?site=` or `x-site`). Fail-open on the serving side
// too: any error / unknown token / lapsed subscriber returns an empty list,
// which the snippet treats as "no enforcement" — never a broken app.
function emptyList() {
  return NextResponse.json({ hashes: [], ttl: 30 }, { headers: { "Cache-Control": "no-store" } });
}

export async function GET(req: NextRequest) {
  try {
    const token = new URL(req.url).searchParams.get("site") ?? req.headers.get("x-site");
    if (!token) return emptyList();

    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("id, is_paid")
      .eq("traffic_ingest_token", token)
      .maybeSingle();

    if (!profile || !profile.is_paid) return emptyList();

    const hashes = await getActiveBlocklist(profile.id as string);
    return NextResponse.json({ hashes, ttl: 30 }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("[traffic/blocklist]", err instanceof Error ? err.message : err);
    return emptyList();
  }
}
