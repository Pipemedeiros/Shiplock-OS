import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { getSupabaseAdmin } from "@/lib/supabase";

export type RateLimitResult =
  | { limited: false; ipHash: string }
  | { limited: true; response: NextResponse };

export async function checkScanRateLimit(req: NextRequest): Promise<RateLimitResult> {
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "anonymous";

  const ipHash = createHash("sha256").update(ip).digest("hex");

  try {
    const db         = getSupabaseAdmin();
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const { count, error } = await db
      .from("scan_logs")
      .select("id", { count: "exact", head: true })
      .eq("ip_hash", ipHash)
      .gte("created_at", oneHourAgo);

    if (error) {
      console.error("[rateLimit] Supabase query error:", error.message);
      return { limited: false, ipHash }; // fail open
    }

    if ((count ?? 0) >= 1) {
      return {
        limited: true,
        response: NextResponse.json(
          { error: "RATE LIMIT EXCEEDED — 1 scan per hour. Upgrade to paid for priority scanning." },
          {
            status: 429,
            headers: {
              "Cache-Control": "no-store",
              "Retry-After": "3600",
              "X-RateLimit-Limit": "1",
              "X-RateLimit-Remaining": "0",
            },
          }
        ),
      };
    }

    return { limited: false, ipHash };
  } catch (err) {
    // Fail open — never block legitimate traffic due to a DB error
    console.error("[rateLimit] Unexpected error:", err);
    return { limited: false, ipHash };
  }
}
