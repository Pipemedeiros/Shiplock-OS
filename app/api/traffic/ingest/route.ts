import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { ingestTrafficEvent } from "@/lib/traffic/ingest";
import { ingestLimiter } from "@/lib/traffic/ingestLimit";
import { getClientIpHash } from "@/lib/rateLimit";

// Public ingest endpoint for the customer's middleware snippet. Auth is the
// per-site traffic_ingest_token (header `x-site` or `?site=`), the same
// unguessable-token model as the deploy webhook. ALWAYS returns a generic
// `{ ok: true }` regardless of outcome — no enumeration, and the snippet
// treats it fire-and-forget anyway. Everything downstream is fail-open.

// Fresh response per call — a Response body is a single-use stream, so a shared
// module-level NextResponse would break under concurrent requests (this is the
// highest-volume endpoint). Same reason the blocklist route uses a function.
const ok = () => NextResponse.json({ ok: true }, { headers: { "Cache-Control": "no-store" } });

const bodySchema = z.object({
  source_id: z.string().min(1).max(64),
  path: z.string().min(1).max(512),
  method: z.string().min(1).max(10),
  ua: z.string().max(512).nullable().optional(),
  session_id: z.string().min(1).max(64).nullable().optional(),
  t: z.number().optional(),
});

export async function POST(req: NextRequest) {
  try {
    // Rate limit BEFORE anything that costs money. Previously every request —
    // including a flood of garbage tokens — bought a database lookup before we
    // knew whether the token was real, so an abusive source ran up our Supabase
    // bill and burned Vercel invocations at will. Bounded per instance now; see
    // lib/traffic/ingestLimit.ts for what that does and does not cover.
    // Silent: the response is generic either way, so a limited caller learns
    // nothing it could use to probe us.
    if (!ingestLimiter.allow(getClientIpHash(req))) return ok();

    const token = req.headers.get("x-site") ?? new URL(req.url).searchParams.get("site");
    if (!token) return ok();

    const parsed = bodySchema.safeParse(await req.json().catch(() => null));
    if (!parsed.success) return ok();

    const admin = getSupabaseAdmin();
    const { data: profile } = await admin
      .from("user_profiles")
      .select("id, email, is_paid")
      .eq("traffic_ingest_token", token)
      .maybeSingle();

    // Unknown token, or a lapsed subscriber — traffic protection pauses with
    // the subscription, same as the rest of the watch. Answer generically.
    if (!profile || !profile.is_paid) return ok();

    const b = parsed.data;
    await ingestTrafficEvent({
      userId: profile.id as string,
      email: (profile.email as string | null) ?? null,
      event: {
        source_id: b.source_id,
        path: b.path,
        method: b.method,
        ua: b.ua ?? null,
        session_id: b.session_id ?? null,
        t: b.t ?? Date.now(),
      },
    });

    return ok();
  } catch (err) {
    console.error("[traffic/ingest]", err instanceof Error ? err.message : err);
    return ok(); // fail open, always generic
  }
}
