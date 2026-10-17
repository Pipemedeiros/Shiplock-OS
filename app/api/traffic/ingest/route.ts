import { PROBE_KINDS } from "@/lib/traffic/probe";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { ingestTrafficEvent } from "@/lib/traffic/ingest";
import { resolveTrafficToken } from "@/lib/traffic/sites";
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
  // A category the snippet classified locally (lib/traffic/probe.ts); an
  // unknown value is dropped, never stored or echoed.
  probe: z.enum(PROBE_KINDS).nullable().optional().catch(null),
  // How the app answered (Express, the Web-standard wrapper); a status code
  // only. Anything else is "not reported", never a guess.
  status: z.number().int().min(100).max(599).nullable().optional().catch(null),
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

    // A site token binds the event to its repository (2F-2a); a legacy
    // account token stays unbound. Unknown, lapsed, or deselected: generic ok.
    const identity = await resolveTrafficToken(token);
    if (!identity) return ok();

    const b = parsed.data;
    await ingestTrafficEvent({
      userId: identity.userId,
      email: identity.email,
      siteId: identity.siteId,
      repositoryId: identity.repositoryId,
      event: {
        source_id: b.source_id,
        path: b.path,
        method: b.method,
        ua: b.ua ?? null,
        session_id: b.session_id ?? null,
        t: b.t ?? Date.now(),
        probe: b.probe ?? null,
        status: b.status ?? null,
      },
    });

    return ok();
  } catch (err) {
    console.error("[traffic/ingest]", err instanceof Error ? err.message : err);
    return ok(); // fail open, always generic
  }
}
