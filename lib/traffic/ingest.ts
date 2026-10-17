import { getSupabaseAdmin } from "@/lib/supabase";
import type { TrafficEvent, TrafficAction } from "@/lib/types";
import {
  computeSignals,
  detect,
  LOOKBACK_MS,
  FETCH_ROW_CAP,
  SESSION_WINDOW_MS,
  scannerAgent,
  type EventRow,
} from "./detect";
import { sendThreatAlert } from "./alerts";

// Orchestrates one mirrored request: record it, score the source over its
// recent window, and act. Everything is fail-open — any DB/analysis error
// returns action "none" and never throws, so the ingest route always answers
// generically and the customer's app (which called us fire-and-forget) is
// never affected. This is the only place in the traffic feature that writes.
export async function ingestTrafficEvent(params: {
  userId: string;
  email: string | null;
  /** Set when the event arrived under a repository-bound traffic site (2F-2a). */
  siteId?: string | null;
  repositoryId?: string | null;
  event: TrafficEvent;
}): Promise<{ action: TrafficAction }> {
  const { userId, email, event } = params;
  try {
    const admin = getSupabaseAdmin();

    // Record the event first so it counts toward its own source's window
    // (same await-before-count reasoning as checkout_attempts in rateLimit.ts).
    await admin.from("traffic_events").insert({
      user_id: userId,
      source_id: event.source_id,
      path: event.path,
      method: event.method,
      ua: event.ua,
      session_id: event.session_id ?? null,
      site_id: params.siteId ?? null,
      repository_id: params.repositoryId ?? null,
      // Only when reported (migration 104); a snippet that cannot see the
      // response sends none and the row is written exactly as before.
      ...(event.status != null ? { status: event.status } : {}),
    });

    const since = new Date(Date.now() - LOOKBACK_MS).toISOString();
    const { data, error } = await admin
      .from("traffic_events")
      .select("path, created_at")
      .eq("user_id", userId)
      .eq("source_id", event.source_id)
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(FETCH_ROW_CAP);

    if (error) {
      console.error("[traffic] event read failed:", error.message);
      return { action: "none" }; // fail open
    }

    const rows = (data ?? []) as EventRow[];
    const capped = rows.length >= FETCH_ROW_CAP;

    // Session-hijack signal: how many DISTINCT sources have presented this
    // request's session recently. Separate query (keyed on session, not
    // source); skipped for anonymous requests. Fail-open — errors -> 0.
    let distinctSourcesForSession = 0;
    if (event.session_id) {
      const sessSince = new Date(Date.now() - SESSION_WINDOW_MS).toISOString();
      const { data: sessRows } = await admin
        .from("traffic_events")
        .select("source_id")
        .eq("user_id", userId)
        .eq("session_id", event.session_id)
        .gte("created_at", sessSince)
        .limit(500);
      distinctSourcesForSession = new Set((sessRows ?? []).map((r) => r.source_id as string)).size;
    }

    const signals = computeSignals(rows, Date.now(), capped, distinctSourcesForSession);
    const agent = scannerAgent(event.ua);
    const decision = detect({ ...signals,
      ...(event.probe ? { probe: { kind: event.probe, path: event.path } } : {}),
      ...(agent ? { agent: { name: agent, path: event.path } } : {}) });

    if (decision.action === "block") {
      const now = Date.now();
      await admin
        .from("traffic_blocklist")
        .upsert(
          {
            user_id: userId,
            source_id: event.source_id,
            reason: decision.reason,
            severity: decision.severity,
            blocked_at: new Date(now).toISOString(),
            expires_at: new Date(now + decision.ttlMs).toISOString(),
          },
          { onConflict: "user_id,source_id" }
        )
        .then(() => {}, (err) => console.error("[traffic] blocklist upsert failed:", err));
    }

    if (decision.action === "block" || decision.action === "alert") {
      await sendThreatAlert(userId, email, event.source_id, decision);
    }

    return { action: decision.action };
  } catch (err) {
    // Never throw — the whole layer is fail-open.
    console.error("[traffic] ingest error:", err instanceof Error ? err.message : err);
    return { action: "none" };
  }
}
