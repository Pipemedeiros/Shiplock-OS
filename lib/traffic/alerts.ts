import { getSupabaseAdmin } from "@/lib/supabase";
import { sendEmail } from "@/lib/email";
import type { Decision } from "@/lib/types";
import { EMAIL_ALERTS_ENABLED } from "@/lib/access";

// Mirrors lib/monitoring/alerts.ts: dedup per (user, source) over a window so a
// flapping attacker doesn't email the customer repeatedly, one Resend send,
// fire-and-forget log insert, errors swallowed (an alert failing must never
// fail the ingest request). Covers both the block and alert tiers — a block
// still tells the customer something happened.
const DEDUP_WINDOW_MS = 6 * 60 * 60 * 1000; // 6h — attacker sources churn faster than scan findings

/** Emails the customer about a blocked or alerting traffic source. */
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
  // Email is parked until Felipe approves delivery and cost. The judgment row
  // below is still written: the graph reads it as "this source was judged".
  const sent = EMAIL_ALERTS_ENABLED && await sendEmail(
    {
      to: email,
      subject: blocked
        ? "ShipLock: malicious traffic blocked"
        : "ShipLock: suspicious traffic detected",
      text: blocked
        ? `ShipLock blocked a source on your app.\n\nReason: ${decision.reason}\nThe block lifts automatically after a cooldown. Sign in to ShipLock to review live traffic protection.`
        : `ShipLock flagged suspicious traffic on your app (not blocked).\n\nReason: ${decision.reason}\nSign in to ShipLock to review live traffic protection.`,
    },
    "traffic"
  );

  // Written even when the email failed — deliberately, and unlike the monitoring
  // alert log, which skips.
  //
  // This row carries TWO meanings: "we notified them" and "this source was
  // judged". lib/traffic/graphFacts.ts reads it as the second, and only ever
  // builds traffic facts from sources already judged here. Skipping the insert
  // to force a retry would therefore erase a security signal the reasoner
  // depends on, to recover a notification about an action that already
  // completed — the block is Tier 1, act-then-report, so the customer's
  // protection does not depend on the email arriving.
  //
  // The monitoring case is the opposite and skips: there, the email IS the
  // notification of something the customer must act on, and the row's only job
  // is suppression. Same-shaped code, opposite correct answer, so the divergence
  // is spelled out rather than left as an inconsistency someone later "fixes".
  if (!sent && EMAIL_ALERTS_ENABLED) {
    console.error(
      `[traffic] alert email failed for user ${userId}; recording the judgment anyway so the graph keeps the signal`
    );
  }

  await admin
    .from("traffic_alert_log")
    .insert({ user_id: userId, source_id: sourceId, reason: decision.reason, action: decision.action })
    .then(() => {}, () => {});
}
