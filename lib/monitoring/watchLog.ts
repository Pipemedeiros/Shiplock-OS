import { getSupabaseAdmin } from "@/lib/supabase";
import type { Finding } from "./findings";

// Dashboard-facing read of the watch's own activity. Counts and metadata
// only — no fix content, so nothing here is paywall-sensitive (titles and
// severities are already preview-safe, and this exposes even less).

type WatchTrigger = "manual" | "deploy" | "hourly" | "scheduled_48h";

interface WatchLogEntry {
  trigger: WatchTrigger;
  createdAt: string;
  findingCount: number;
  criticalCount: number;
  // Findings present in this snapshot but not the previous one — the same
  // stable-id diff the alert engine uses (lib/monitoring/diff.ts), computed
  // over the fetched window. Null for the oldest fetched row, where there is
  // no previous snapshot to compare against.
  newCount: number | null;
}

interface SnapshotRow {
  trigger_source: WatchTrigger;
  created_at: string;
  findings: Finding[];
}

// Pure so it can be unit-tested: rows must be ordered newest-first, exactly
// as the query below returns them. The extra oldest row (if any) only
// exists to give the last displayed row a comparison baseline.
export function annotateWatchLog(rows: SnapshotRow[], displayLimit: number): WatchLogEntry[] {
  return rows.slice(0, displayLimit).map((row, i) => {
    const previous = rows[i + 1];
    const previousIds = previous ? new Set(previous.findings.map((f) => f.id)) : null;
    return {
      trigger: row.trigger_source,
      createdAt: row.created_at,
      findingCount: row.findings.length,
      criticalCount: row.findings.filter((f) => f.severity === "CRITICAL").length,
      newCount: previousIds ? row.findings.filter((f) => !previousIds.has(f.id)).length : null,
    };
  });
}


interface WatchStatus {
  enabled: boolean;
  webhookToken: string | null;
  lastDeepScanAt: string | null;
}

/** Whether monitoring is on for the account and when it last ran. */
export async function getWatchStatus(userId: string): Promise<WatchStatus> {
  const admin = getSupabaseAdmin();
  const { data } = await admin
    .from("user_profiles")
    .select("monitoring_enabled, monitor_webhook_token, last_monitored_at")
    .eq("id", userId)
    .maybeSingle();
  return {
    enabled: data?.monitoring_enabled ?? false,
    webhookToken: data?.monitor_webhook_token ?? null,
    lastDeepScanAt: data?.last_monitored_at ?? null,
  };
}
