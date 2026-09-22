import type { Finding } from "./findings";
import { sendEmail } from "@/lib/email";
import { getSupabaseAdmin } from "@/lib/supabase";
import { EMAIL_ALERTS_ENABLED } from "@/lib/access";

const DEDUP_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// Sends one email per new-finding batch, and never re-alerts the same
// finding id for the same user within 7 days — covers the case where a
// check flaps (fails, resolves, fails again) and would otherwise look
// "new" twice in a short window. Silently skips already-alerted findings
// rather than filtering the whole batch, so a mix of genuinely-new and
// recently-alerted findings still sends for the new ones.
export async function sendNewFindingsAlert(
  userId: string,
  email: string,
  newFindings: Finding[]
): Promise<"sent" | "skipped" | "failed"> {
  if (newFindings.length === 0) return "skipped";

  // Parked for the MVP alongside billing (lib/access.ts). The dedup log, the
  // 7-day window and the copy all stay exactly as they are — we simply do not
  // send, because an MVP tester does not want mail from a tool they are still
  // deciding about. Findings still surface in the dashboard on every pass.
  if (!EMAIL_ALERTS_ENABLED) return "skipped";

  const admin = getSupabaseAdmin();
  const cutoff = new Date(Date.now() - DEDUP_WINDOW_MS).toISOString();

  const { data: recentlyAlerted } = await admin
    .from("monitoring_alert_log")
    .select("finding_id")
    .eq("user_id", userId)
    .gte("alerted_at", cutoff);

  const recentIds = new Set((recentlyAlerted ?? []).map((r) => r.finding_id as string));
  const toAlert = newFindings.filter((f) => !recentIds.has(f.id));
  if (toAlert.length === 0) return "skipped";

  const lines = toAlert.map((f) => `- [${f.severity}] ${f.title}\n  ${f.consequence}`).join("\n\n");

  const sent = await sendEmail(
    {
      to: email,
      subject: `ShipLock — ${toAlert.length} new issue${toAlert.length !== 1 ? "s" : ""} found`,
      text: `ShipLock found ${toAlert.length} new issue${toAlert.length !== 1 ? "s" : ""} on your monitored project:\n\n${lines}\n\nSign in to ShipLock for the exact fix and code prompt for each.`,
    },
    "monitoring"
  );

  // Only record the dedup rows when the email actually went out.
  //
  // This insert is what suppresses re-alerting for 7 days. Writing it after a
  // failed send meant a customer who was never told still counted as told: the
  // finding stays open in every later snapshot, is filtered out as
  // "recently alerted" on every subsequent pass, and no email is sent for a
  // week. For a leaked service-role key that is a week of silence on the most
  // urgent thing this product detects.
  //
  // Failing to write it is the safe direction: the worst case is one duplicate
  // email if the send succeeded but the insert did not, which is strictly better
  // than silence about a CRITICAL finding.
  if (!sent) {
    console.error(
      `[monitoring] not recording dedup for ${toAlert.length} finding(s) for user ${userId} — email did not send, so they stay eligible for the next pass`
    );
    return "failed";
  }

  await admin
    .from("monitoring_alert_log")
    .insert(toAlert.map((f) => ({ user_id: userId, finding_id: f.id })))
    .then(() => {}, () => {});
  return "sent";
}
