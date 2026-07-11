import { scanProject, scanCriticalChecks } from "@/lib/scanner";
import { decrypt } from "@/lib/crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import {
  extractFindings,
  extractCriticalFindings,
  isCriticalScopeFindingId,
  type Finding,
} from "./findings";
import { diffSnapshots } from "./diff";
import { sendNewFindingsAlert } from "./alerts";

export interface MonitoredProfile {
  id: string;
  email: string | null;
  monitored_project_url: string;
  monitored_anon_key_encrypted: string;
}

export type TriggerSource = "deploy" | "hourly" | "scheduled_48h";

// Shared by all three monitoring entry points (deploy webhook, hourly cron,
// 48h cron): run the scan (depth depends on trigger — see below), diff
// against the most recent snapshot (regardless of which trigger produced
// it — a hurried hourly pass and a full 48h pass both write to the same
// snapshot history, so an hourly run correctly sees findings a full scan
// surfaced two days ago, and vice versa), store the new snapshot, alert on
// genuinely new findings only.
export async function runMonitoringPass(
  profile: MonitoredProfile,
  triggerSource: TriggerSource
): Promise<{ newFindingsCount: number }> {
  const admin = getSupabaseAdmin();
  const anonKey = decrypt(profile.monitored_anon_key_encrypted);

  const { data: lastSnapshot } = await admin
    .from("monitoring_snapshots")
    .select("findings")
    .eq("user_id", profile.id)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const previousFindings = (lastSnapshot?.findings ?? []) as Finding[];

  // Hourly uses the lightweight 4-check pass (lib/scanner.ts
  // scanCriticalChecks); deploy and the 48h scheduled pass use the full
  // 16-check scan. Since check 16 (public storage buckets) was promoted
  // into the full scan too, the full scan's own coverage is now a
  // strict superset of the hourly pass's scope — full-scan triggers no
  // longer need to carry anything forward, their fresh results are always
  // complete. The hourly pass is still narrower than the full scan (it
  // skips 12 checks entirely), so its findings for everything outside its
  // own scope must still be carried forward unchanged from the previous
  // snapshot — if a narrower pass silently replaced the whole snapshot,
  // out-of-scope findings would vanish and look "resolved" (they were just
  // not re-checked), which would then make them look "new" again on the
  // next wider pass: a spurious duplicate alert for something that was
  // never actually fixed.
  let currentFindings: Finding[];
  if (triggerSource === "hourly") {
    const fresh = extractCriticalFindings(
      await scanCriticalChecks(profile.monitored_project_url, anonKey)
    );
    const carriedForward = previousFindings.filter((f) => !isCriticalScopeFindingId(f.id));
    currentFindings = [...carriedForward, ...fresh];
  } else {
    currentFindings = extractFindings(await scanProject(profile.monitored_project_url, anonKey));
  }

  const { newFindings } = diffSnapshots(previousFindings, currentFindings);

  await admin
    .from("monitoring_snapshots")
    .insert({
      user_id: profile.id,
      trigger_source: triggerSource,
      findings: currentFindings,
    })
    .then(() => {}, () => {});

  // Only full scans count toward "when was this user last actually
  // checked" for the 48h staleness filter in /api/monitor/scheduled. If
  // the hourly lightweight pass refreshed this too, a user with hourly
  // monitoring enabled would never look stale enough for the full 16-check
  // scan to run again — the hourly cron ticks far more often than 48h and
  // would keep the timestamp perpetually fresh.
  if (triggerSource !== "hourly") {
    await admin
      .from("user_profiles")
      .update({ last_monitored_at: new Date().toISOString() })
      .eq("id", profile.id)
      .then(() => {}, () => {});
  }

  if (newFindings.length > 0 && profile.email) {
    await sendNewFindingsAlert(profile.id, profile.email, newFindings);
  }

  return { newFindingsCount: newFindings.length };
}
