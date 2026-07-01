import { scanProject } from "@/lib/scanner";
import { decrypt } from "@/lib/crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import { extractFindings } from "./findings";
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
// 48h cron): decrypt the stored key, run the scan, diff against the most
// recent snapshot (regardless of which trigger produced it — a hurried
// hourly pass and a full 48h pass both write to the same snapshot history,
// so an hourly run correctly sees findings a full scan surfaced two days
// ago, and vice versa), store the new snapshot, alert on genuinely new
// findings only.
export async function runMonitoringPass(
  profile: MonitoredProfile,
  triggerSource: TriggerSource
): Promise<{ newFindingsCount: number }> {
  const admin = getSupabaseAdmin();
  const anonKey = decrypt(profile.monitored_anon_key_encrypted);

  const scan = await scanProject(profile.monitored_project_url, anonKey);
  const currentFindings = extractFindings(scan);

  const { data: lastSnapshot } = await admin
    .from("monitoring_snapshots")
    .select("findings")
    .eq("user_id", profile.id)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const previousFindings = (lastSnapshot?.findings ?? []) as Awaited<
    ReturnType<typeof extractFindings>
  >;

  const { newFindings } = diffSnapshots(previousFindings, currentFindings);

  await admin
    .from("monitoring_snapshots")
    .insert({
      user_id: profile.id,
      trigger_source: triggerSource,
      findings: currentFindings,
    })
    .then(() => {}, () => {});

  await admin
    .from("user_profiles")
    .update({ last_monitored_at: new Date().toISOString() })
    .eq("id", profile.id)
    .then(() => {}, () => {});

  if (newFindings.length > 0 && profile.email) {
    await sendNewFindingsAlert(profile.id, profile.email, newFindings);
  }

  return { newFindingsCount: newFindings.length };
}
