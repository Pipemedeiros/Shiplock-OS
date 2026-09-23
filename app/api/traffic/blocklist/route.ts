import { NextRequest, NextResponse } from "next/server";
import { getActiveBlocklist } from "@/lib/traffic/blocklist";
import { resolveTrafficToken } from "@/lib/traffic/sites";

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

    // Same token model as ingest: a site token or the legacy account token.
    const identity = await resolveTrafficToken(token);
    if (!identity) return emptyList();

    const hashes = await getActiveBlocklist(identity.userId);
    return NextResponse.json({ hashes, ttl: 30 }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("[traffic/blocklist]", err instanceof Error ? err.message : err);
    return emptyList();
  }
}
