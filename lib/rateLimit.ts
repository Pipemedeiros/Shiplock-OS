import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

export type RateLimitResult =
  | { limited: false; ipHash: string }
  | { limited: true; response: NextResponse };

// x-forwarded-for is a comma-separated hop chain: "client-claimed, ..., nearest-proxy".
// Each hop APPENDS its own observed peer IP rather than replacing what came before,
// so the first entry is whatever the caller claims (fully attacker-controlled) and
// the last entry is what our nearest trusted proxy (e.g. Vercel's edge) actually saw.
// x-real-ip, when present, is set directly by the proxy and isn't a hop chain at all.
// NOTE: this only holds when there genuinely is a trusted proxy in front of the app
// (e.g. deployed on Vercel). In local dev there is no proxy, so this header is fully
// attacker-controlled either way — confirmed during the 2026-06-22 security audit.
export function getClientIpHash(req: NextRequest): string {
  const realIp = req.headers.get("x-real-ip");
  const forwardedChain = req.headers.get("x-forwarded-for");
  const lastHop = forwardedChain?.split(",").pop()?.trim();
  const ip = realIp || lastHop || "anonymous";
  return createHash("sha256").update(ip).digest("hex");
}

async function checkDbRateLimit(
  table: string,
  ipHash: string,
  windowMs: number,
  maxRequests: number,
  limitedResponse: () => NextResponse
): Promise<RateLimitResult> {
  try {
    const db = getSupabaseAdmin();
    const windowStart = new Date(Date.now() - windowMs).toISOString();

    const { count, error } = await db
      .from(table)
      .select("id", { count: "exact", head: true })
      .eq("ip_hash", ipHash)
      .gte("created_at", windowStart);

    if (error) {
      console.error(`[rateLimit] Supabase query error on ${table}:`, error.message);
      return { limited: false, ipHash }; // fail open
    }

    if ((count ?? 0) >= maxRequests) {
      return { limited: true, response: limitedResponse() };
    }

    return { limited: false, ipHash };
  } catch (err) {
    // Fail open — never block legitimate traffic due to a DB error
    console.error(`[rateLimit] Unexpected error on ${table}:`, err);
    return { limited: false, ipHash };
  }
}

export async function checkScanRateLimit(req: NextRequest): Promise<RateLimitResult> {
  const ipHash = getClientIpHash(req);
  return checkDbRateLimit("scan_logs", ipHash, 60 * 60 * 1000, 1, () =>
    NextResponse.json(
      { error: "Rate limit exceeded: one scan per hour. Please retry later." },
      {
        status: 429,
        headers: {
          "Cache-Control": "no-store",
          "Retry-After": "3600",
          "X-RateLimit-Limit": "1",
          "X-RateLimit-Remaining": "0",
        },
      }
    )
  );
}
