import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import { scanProject, ScanError } from "@/lib/scanner";
import { runExposedPathScan } from "@/lib/security/exposedPathsRun";
import { analyzeResult } from "@/lib/analyzer";
import { validateSupabaseUrl, validateAnonKey, validateAppUrl, ValidationError } from "@/lib/sanitize";
import { getClientIpHash } from "@/lib/rateLimit";
import { getSupabaseAdmin } from "@/lib/supabase";
import { encrypt } from "@/lib/crypto";
import { extractFindings } from "@/lib/monitoring/findings";

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }
  const { supabaseUrl: rawUrl, anonKey: rawAnonKey, appUrl: rawAppUrl } = (body ?? {}) as Record<string, unknown>;

  let supabaseUrl: string;
  let anonKey: string;
  let appUrl: string | undefined;
  try {
    supabaseUrl = validateSupabaseUrl(rawUrl);
    anonKey = validateAnonKey(rawAnonKey);
    // Optional — absence is fine, only validate if the caller sent something.
    if (typeof rawAppUrl === "string" && rawAppUrl.length > 0) {
      appUrl = validateAppUrl(rawAppUrl);
    }
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
    scanResult = await scanProject(supabaseUrl, anonKey, appUrl);
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
      issue_count: analysis.issues.length,
      critical_count: criticalCount,
      ip_hash: ipHash,
    })
    .then(() => {}, () => {});

  // Enroll this project in continuous monitoring — the landing page and
  // privacy policy both describe monitoring as starting from the first
  // scan, and until this write existed nothing ever set monitoring_enabled
  // or stored the credentials the hourly/48h/deploy passes read (the
  // Stripe webhook only ever sets it false on cancellation). The watched
  // URL is stored raw — migration 008 created monitored_project_url for
  // exactly this, and a re-scan needs a real address, not a hash; the
  // privacy page discloses it. Never retain a service-role key, though:
  // scanning with one is flagged CRITICAL and returned to the user, but
  // keeping an admin credential at rest for background re-scans is a
  // different risk than analyzing it once in memory.
  if (!scanResult.keyAnalysis.isServiceRole) {
    // These two writes are load-bearing for monitoring correctness, so —
    // unlike the fire-and-forget bookkeeping inserts around them — they are
    // awaited: the enrollment update is what the hourly/48h/deploy passes
    // key on, and the baseline snapshot is what stops the first pass from
    // re-alerting every finding the user just saw in this response
    // (migration 023 adds 'manual' to the trigger_source constraint for it).
    // Awaiting also guarantees both have committed before the response
    // returns, so an immediate dashboard load or a cron tick can't race a
    // half-written enrollment. Errors are logged, never surfaced — a failed
    // enrollment must not fail the scan the user paid for; the next scan
    // re-attempts it.
    try {
      await admin
        .from("user_profiles")
        .update({
          monitoring_enabled: true,
          monitored_project_url: supabaseUrl,
          monitored_anon_key_encrypted: encrypt(anonKey),
          // Persist the app URL (when given) so exposed-path probes can re-run
          // later, not just at scan time. Raw, like monitored_project_url.
          ...(appUrl ? { monitored_app_url: appUrl } : {}),
        })
        .eq("id", userId);

      await admin.from("monitoring_snapshots").insert({
        user_id: userId,
        trigger_source: "manual",
        findings: extractFindings(scanResult),
      });

      // Dynamic exposed-path probes against the live app (git repo, DB dumps,
      // credential files) — complements the scanner's .env checks. Best-effort;
      // findings land in deep_findings and surface everywhere the others do.
      if (appUrl) {
        try {
          await runExposedPathScan(userId, appUrl);
        } catch (e) {
          console.error("[scan] exposed-path probe failed:", e instanceof Error ? e.message : e);
        }
      }
    } catch (err) {
      console.error(
        "[scan] monitoring enrollment failed (scan result still returned):",
        err instanceof Error ? err.message : err
      );
    }
  }

  admin
    .from("scan_history")
    .insert({
      user_id: userId,
      project_url_hash: urlHash,
      issue_count: analysis.issues.length,
      full_issues: fullIssues,
      preview_issues: previewIssues,
    })
    .then(() => {}, () => {});

  // PAYWALL ENFORCED — this route is unreachable for a non-paid caller
  // (gated above), so the response is always the full shape.
  return NextResponse.json(
    {
      summary: analysis.summary,
      isPaid: true,
      issues: fullIssues,
      appUrlChecked: scanResult.appUrlChecked,
      monitoringEnrolled: !scanResult.keyAnalysis.isServiceRole,
    },
    { headers: { "Cache-Control": "no-store" } }
  );
}
