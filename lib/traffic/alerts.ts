import { Resend } from "resend";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { Decision } from "@/lib/types";

// Mirrors lib/monitoring/alerts.ts: dedup per (user, source) over a window so a
// flapping attacker doesn't email the customer repeatedly, one Resend send,
// fire-and-forget log insert, errors swallowed (an alert failing must never
// fail the ingest request). Covers both the block and alert tiers — a block
// still tells the customer something happened.
const DEDUP_WINDOW_MS = 6 * 60 * 60 * 1000; // 6h — attacker sources churn faster than scan findings

export async function sendThreatAlert(
  userId: string,
  email: string | null,
  sourceId: string,
  decision: Decision
): Promise<void> {
  if (!email) return;
  if (decision.action !== "block" && decision.action !== "alert") return;

  const admin = getSupabaseAdmin();
  const cutoff = new Date(Date.now() - DEDUP_WINDOW_MS).toISOString();

  // Dedup per (source, ACTION) — so a source that alerted (elevated auth) and
  // then escalates to a block still sends the "blocked" email, while repeat
  // blocks / repeat alerts stay deduped.
  const { data: recent } = await admin
    .from("traffic_alert_log")
    .select("id")
    .eq("user_id", userId)
    .eq("source_id", sourceId)
    .eq("action", decision.action)
    .gte("alerted_at", cutoff)
    .limit(1);

  if (recent && recent.length > 0) return; // already told them about this source+action recently

  const blocked = decision.action === "block";
  const resend = new Resend(process.env.RESEND_API_KEY);
  await resend.emails
    .send({
      from: process.env.RESEND_FROM_EMAIL!,
      to: email,
      subject: blocked
        ? "ShipLock — malicious traffic blocked"
        : "ShipLock — suspicious traffic detected",
      text: blocked
        ? `ShipLock blocked a source on your app.\n\nReason: ${decision.reason}\nThe block lifts automatically after a cooldown. Sign in to ShipLock to review live traffic protection.`
        : `ShipLock flagged suspicious traffic on your app (not blocked).\n\nReason: ${decision.reason}\nSign in to ShipLock to review live traffic protection.`,
    })
    .catch((err) => {
      console.error("[traffic] alert email failed:", err instanceof Error ? err.message : err);
    });

  await admin
    .from("traffic_alert_log")
    .insert({ user_id: userId, source_id: sourceId, reason: decision.reason, action: decision.action })
    .then(() => {}, () => {});
}
