import { Resend } from "resend";
import type { Finding } from "./findings";
import { getSupabaseAdmin } from "@/lib/supabase";

const DEDUP_WINDOW_MS = 7 * 24 * 60 * 60 * 1000; // 7 days, per CLAUDE.md

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
): Promise<void> {
  if (newFindings.length === 0) return;

  const admin = getSupabaseAdmin();
  const cutoff = new Date(Date.now() - DEDUP_WINDOW_MS).toISOString();

  const { data: recentlyAlerted } = await admin
    .from("monitoring_alert_log")
    .select("finding_id")
    .eq("user_id", userId)
    .gte("alerted_at", cutoff);

  const recentIds = new Set((recentlyAlerted ?? []).map((r) => r.finding_id as string));
  const toAlert = newFindings.filter((f) => !recentIds.has(f.id));
  if (toAlert.length === 0) return;

  const resend = new Resend(process.env.RESEND_API_KEY);
  const lines = toAlert.map((f) => `- [${f.severity}] ${f.title}\n  ${f.consequence}`).join("\n\n");

  await resend.emails
    .send({
      from: process.env.RESEND_FROM_EMAIL!,
      to: email,
      subject: `ShipLock — ${toAlert.length} new issue${toAlert.length !== 1 ? "s" : ""} found`,
      text: `Loki found ${toAlert.length} new issue${toAlert.length !== 1 ? "s" : ""} on your monitored project:\n\n${lines}\n\nSign in to ShipLock for the exact fix and code prompt for each.`,
    })
    .catch((err) => {
      console.error("[monitoring] alert email send failed:", err instanceof Error ? err.message : err);
    });

  await admin
    .from("monitoring_alert_log")
    .insert(toAlert.map((f) => ({ user_id: userId, finding_id: f.id })))
    .then(() => {}, () => {});
}
