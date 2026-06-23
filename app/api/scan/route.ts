import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { scanProject, ScanError } from "@/lib/scanner";
import { analyzeResult } from "@/lib/analyzer";
import { validateSupabaseUrl, validateAnonKey, ValidationError } from "@/lib/sanitize";
import { checkScanRateLimit, getClientIpHash } from "@/lib/rateLimit";
import { getSupabaseAdmin, getSupabaseUser } from "@/lib/supabase";

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

  // Identify the caller and their paid status, if authenticated
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  let userId: string | null = null;
  let isPaid = false;

  if (token) {
    const { data } = await admin.auth.getUser(token);
    if (data.user) {
      userId = data.user.id;
      const { data: profile } = await admin
        .from("user_profiles")
        .select("is_paid")
        .eq("id", data.user.id)
        .single();
      isPaid = profile?.is_paid ?? false;
    }
  }

  // Rate limiting — an available bonus scan bypasses the 1/hour IP limit.
  // use_bonus_scan() takes no params and resolves the caller via auth.uid(),
  // so it must be called through the user's own JWT (getSupabaseUser), not
  // the service-role client — auth.uid() would be null under service role.
  const useBonusScan = req.headers.get("x-bonus-scan") === "1" && userId !== null;
  let ipHash: string;

  if (useBonusScan) {
    const { data: remaining, error } = await getSupabaseUser(token!).rpc("use_bonus_scan");
    if (error || remaining === -1) {
      return NextResponse.json({ error: "No bonus scans available." }, { status: 429 });
    }
    ipHash = getClientIpHash(req);
  } else {
    const limit = await checkScanRateLimit(req);
    if (limit.limited) return limit.response;
    ipHash = limit.ipHash;
  }

  // Run the 15-check attack suite
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

  // Paywall-enforced response shapes — fix and codefix never leave this function for free callers
  const previewIssues = analysis.issues.map(({ title, severity, consequence }) => ({
    title,
    severity,
    consequence,
  }));
  const fullIssues = analysis.issues; // includes fix and codefix

  // Never store the raw project URL or anon key — hash only
  const urlHash = createHash("sha256").update(supabaseUrl).digest("hex");
  const criticalCount = analysis.issues.filter((i) => i.severity === "CRITICAL").length;

  // Awaited (not fire-and-forget): this row is what the next request's rate
  // limit check counts against. Firing it without awaiting created a race —
  // a client sending requests back-to-back could have its next request's
  // count-check run before this insert committed, slipping past the 1/hour
  // limit. Confirmed via 3 rapid sequential requests during the 2026-06-22
  // security audit (2nd request succeeded when it should have been blocked).
  const { error: logError } = await admin.from("scan_logs").insert({
    project_ref: urlHash.slice(-6),
    grade: analysis.grade,
    issue_count: analysis.issues.length,
    critical_count: criticalCount,
    ip_hash: ipHash,
  });
  if (logError) console.error("[scan] scan_logs insert error:", logError.message);

  if (userId) {
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
  }

  // PAYWALL ENFORCED — free users never receive fix or codefix
  return NextResponse.json(
    {
      grade: analysis.grade,
      summary: analysis.summary,
      isPaid,
      issues: isPaid ? fullIssues : previewIssues,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
