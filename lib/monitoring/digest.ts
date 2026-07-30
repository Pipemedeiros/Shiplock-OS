import { Resend } from "resend";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getLatestScan } from "@/lib/scanHistory";
import type { Severity } from "@/lib/types";

// The weekly digest — the churn countermeasure.
//
// Alerts fire only on NEW findings, which is correct: silence is the default
// and re-alerting known issues trains people to ignore us. But it means a
// customer four months in hears nothing, and "nothing is wrong" is
// indistinguishable from "this product is dead". They cancel while the thing
// is working perfectly.
//
// This is not an alert. It is a receipt: how many passes ran, how many pull
// requests were checked, what we turned away, what got fixed. Evidence, sent
// whether or not anything happened — because "nothing happened" is exactly the
// message worth paying for, as long as it arrives with proof attached.
//
// Rules it must not break:
//  - No fix content, ever. Titles and counts only; the paywall lives in the app.
//  - Never claim a window wider than the data. traffic_events is pruned at 48h,
//    so request volume is reported as 48h even though the digest is weekly.
//  - Honest when idle: if we genuinely did nothing (no passes at all), say so
//    rather than dressing up zeros.

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;
const TRAFFIC_WINDOW_HOURS = 48; // traffic_events retention — see lib/traffic/prune.ts

export interface DigestData {
  passes: number;
  newFindings: number;
  resolvedFindings: number;
  openFindings: number;
  openCritical: number;
  requestsWatched: number;
  threatsHandled: number;
  /** False when nothing ran at all — don't send a receipt for no work. */
  worthSending: boolean;
}

export async function collectDigest(userId: string): Promise<DigestData> {
  const admin = getSupabaseAdmin();
  const weekAgo = new Date(Date.now() - WEEK_MS).toISOString();
  const trafficSince = new Date(Date.now() - TRAFFIC_WINDOW_HOURS * 60 * 60 * 1000).toISOString();

  const [passes, resolved, open, critical, threats, pulse] = await Promise.all([
    admin
      .from("monitoring_snapshots")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gte("created_at", weekAgo),
    admin
      .from("deep_findings")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gte("archived_at", weekAgo),
    admin
      .from("deep_findings")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .is("archived_at", null),
    admin
      .from("deep_findings")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .is("archived_at", null)
      .eq("severity", "CRITICAL"),
    admin
      .from("traffic_alert_log")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gte("alerted_at", weekAgo),
    admin
      .from("traffic_events")
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
      .gte("created_at", trafficSince),
  ]);

  const newFindings = await admin
    .from("deep_findings")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .gte("detected_at", weekAgo);

  // CRITICAL: deep_findings holds ONLY the deep sources (github, policy,
  // exposed-path, advisor). The 16-check scan's findings live in
  // scan_history.full_issues — a different table entirely. Counting only
  // deep_findings would tell a customer with 4 open scan findings, one of them
  // critical, that "nothing is open" — the exact inverse of the truth, in the
  // one email whose entire purpose is to be a truthful record. Merge both, the
  // same way lib/fixes/findings.ts does for the dashboard.
  const latest = await getLatestScan(userId);
  const scanIssues = (latest?.full_issues ?? []) as { severity: Severity }[];
  const scanOpen = scanIssues.length;
  const scanCritical = scanIssues.filter((i) => i.severity === "CRITICAL").length;

  const passCount = passes.count ?? 0;
  const requestsWatched = pulse.count ?? 0;

  return {
    passes: passCount,
    newFindings: newFindings.count ?? 0,
    resolvedFindings: resolved.count ?? 0,
    openFindings: (open.count ?? 0) + scanOpen,
    openCritical: (critical.count ?? 0) + scanCritical,
    requestsWatched,
    threatsHandled: threats.count ?? 0,
    // If nothing ran and we saw no traffic, there is no work to report and a
    // digest would be noise pretending to be reassurance.
    worthSending: passCount > 0 || requestsWatched > 0,
  };
}

export function buildDigestText(d: DigestData, appUrl: string): string {
  const lines: string[] = [];

  const headline =
    d.openCritical > 0
      ? `${d.openCritical} critical issue${d.openCritical === 1 ? "" : "s"} still open.`
      : d.openFindings > 0
        ? `Nothing critical open. ${d.openFindings} finding${d.openFindings === 1 ? "" : "s"} still waiting.`
        : "Nothing new, and nothing open.";

  lines.push(headline);
  lines.push("");
  lines.push("Here's the week:");
  lines.push("");

  if (d.passes > 0) {
    lines.push(`  ${d.passes} monitoring pass${d.passes === 1 ? "" : "es"} run against your project`);
  }
  if (d.requestsWatched > 0) {
    lines.push(
      `  ${d.requestsWatched.toLocaleString()} requests checked at your front door (last ${TRAFFIC_WINDOW_HOURS}h)`
    );
  }
  if (d.threatsHandled > 0) {
    lines.push(`  ${d.threatsHandled} source${d.threatsHandled === 1 ? "" : "s"} flagged or turned away`);
  }
  if (d.resolvedFindings > 0) {
    lines.push(`  ${d.resolvedFindings} finding${d.resolvedFindings === 1 ? "" : "s"} resolved`);
  }
  if (d.newFindings > 0) {
    lines.push(`  ${d.newFindings} new finding${d.newFindings === 1 ? "" : "s"} — details in your dashboard`);
  }

  lines.push("");
  lines.push(
    d.newFindings === 0
      ? "We didn't email you this week because nothing new appeared. That's the product working, not a gap in it — this note is just the proof."
      : "New findings were alerted separately when we found them; this is the summary."
  );
  lines.push("");
  lines.push(`${appUrl.replace(/\/+$/, "")}/dashboard`);
  lines.push("");
  lines.push("To stop these weekly notes, reply to this email and we'll turn them off.");

  return lines.join("\n");
}

/**
 * Sends the weekly digest if one is due. Fail-soft — a digest is never allowed
 * to break the cron pass that calls it.
 */
export async function sendWeeklyDigest(
  userId: string,
  email: string | null,
  lastSentAt: string | null
): Promise<boolean> {
  if (!email) return false;
  if (lastSentAt && Date.now() - Date.parse(lastSentAt) < WEEK_MS) return false;

  const data = await collectDigest(userId);
  if (!data.worthSending) return false;

  const admin = getSupabaseAdmin();
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "";

  const subject =
    data.openCritical > 0
      ? `ShipLock — ${data.openCritical} critical still open`
      : data.newFindings > 0
        ? "ShipLock — your week in review"
        : "ShipLock — all quiet, and here's the proof";

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL!,
      to: email,
      subject,
      text: buildDigestText(data, appUrl),
    });
  } catch (err) {
    console.error("[digest] send failed:", err instanceof Error ? err.message : err);
    return false;
  }

  await admin
    .from("user_profiles")
    .update({ last_digest_sent_at: new Date().toISOString() })
    .eq("id", userId)
    .then(
      () => {},
      () => {}
    );

  return true;
}
