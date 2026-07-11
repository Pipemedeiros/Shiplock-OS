import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { scanProject, ScanError } from "@/lib/scanner";
import { analyzeResult } from "@/lib/analyzer";
import { validateSupabaseUrl, validateAnonKey, ValidationError } from "@/lib/sanitize";
import { getClientIpHash } from "@/lib/rateLimit";
import { getSupabaseAdmin } from "@/lib/supabase";

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const { supabaseUrl: rawUrl, anonKey: rawAnonKey } = (body ?? {}) as Record<string, unknown>;

  let supabaseUrl: string;
  let anonKey: string;
  try {
    supabaseUrl = validateSupabaseUrl(rawUrl);
    anonKey = validateAnonKey(rawAnonKey);
  } catch (err) {
    if (err instanceof ValidationError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    throw err;
  }

  const admin = getSupabaseAdmin();

  // Scanning is paid-only — no free tier, no anonymous callers. Never trust
  // a client-supplied paid flag; is_paid is always read fresh from the DB.
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Sign in and subscribe to run a scan." }, { status: 401 });
  }
  const { data: authData } = await admin.auth.getUser(token);
  if (!authData.user) {
    return NextResponse.json({ error: "Sign in and subscribe to run a scan." }, { status: 401 });
  }
  const userId = authData.user.id;

  const { data: profile } = await admin
    .from("user_profiles")
    .select("is_paid")
    .eq("id", userId)
    .single();
  if (!profile?.is_paid) {
    return NextResponse.json({ error: "Subscribe to run a scan." }, { status: 402 });
  }

  // No rate-limit gate here — a paid, authenticated caller doesn't need
  // free-tier abuse prevention. ip_hash is still recorded on the scan_logs
  // row below purely for the future activity-ticker roadmap item, not for
  // limiting.
  const ipHash = getClientIpHash(req);

  // Run the 16-check attack suite
  let scanResult;
  try {
    scanResult = await scanProject(supabaseUrl, anonKey);
  } catch (err) {
    if (err instanceof ScanError) {
      return NextResponse.json({ error: err.message }, { status: err.statusCode ?? 400 });
    }
    return NextResponse.json(
      { error: "Scan failed — check your project URL and anon key." },
      { status: 500 }
    );
  }

  const analysis = await analyzeResult(scanResult);

  // scan_history stores both shapes regardless of paywall status at scan
  // time — the dashboard picks preview vs. full based on the caller's
  // CURRENT is_paid at read time (lib/scanHistory.ts), e.g. for a lapsed
  // subscriber viewing an old scan. This route's own response, below, is
  // always the full shape now — every caller who reaches this point is
  // paid, by construction.
  const previewIssues = analysis.issues.map(({ title, severity, consequence }) => ({
    title,
    severity,
    consequence,
  }));
  const fullIssues = analysis.issues; // includes fix and codefix

  // Never store the raw project URL or anon key — hash only
  const urlHash = createHash("sha256").update(supabaseUrl).digest("hex");
  const criticalCount = analysis.issues.filter((i) => i.severity === "CRITICAL").length;

  // scan_logs no longer gates any rate limit on this route (paid+authed
  // callers don't need free-tier abuse prevention) — this insert exists
  // purely to keep data flowing for the future activity-ticker roadmap
  // item, so it's fire-and-forget rather than awaited.
  admin
    .from("scan_logs")
    .insert({
      project_ref: urlHash.slice(-6),
      grade: analysis.grade,
      issue_count: analysis.issues.length,
      critical_count: criticalCount,
      ip_hash: ipHash,
    })
    .then(() => {}, () => {});

  admin
    .from("scan_history")
    .insert({
      user_id: userId,
      project_url_hash: urlHash,
      grade: analysis.grade,
      issue_count: analysis.issues.length,
      full_issues: fullIssues,
      preview_issues: previewIssues,
    })
    .then(() => {}, () => {});

  // PAYWALL ENFORCED — this route is unreachable for a non-paid caller
  // (gated above), so the response is always the full shape.
  return NextResponse.json(
    {
      grade: analysis.grade,
      summary: analysis.summary,
      isPaid: true,
      issues: fullIssues,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
