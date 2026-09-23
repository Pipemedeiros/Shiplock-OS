import { decrypt } from "@/lib/crypto";
import { getSupabaseAdmin } from "@/lib/supabase";
import type { Finding } from "./findings";
import { diffSnapshots } from "./diff";
import { saveFacts } from "@/lib/graph/graphRun";
import { runCollectors, type CollectorSpec, type ProviderCommit } from "./registry";
import { DEFAULT_COLLECTORS } from "./collectors";
import type { MonitoredProfile, TriggerSource } from "./types";

// Re-exported so every existing import site keeps working; the definitions moved
// to ./types to break a cycle with the registry.
export type { MonitoredProfile, TriggerSource } from "./types";

// Shared by all three monitoring entry points (deploy webhook, hourly cron, 48h
// cron). The shape is deliberately a spine, not a ladder: run the eligible
// collectors, merge what they produced, diff against the most recent snapshot,
// store, and return genuinely new findings; the worker queues their alert.
//
// Diffing is against the most recent snapshot regardless of which trigger
// produced it — a hurried hourly pass and a full 48h pass write to the same
// history, so an hourly run correctly sees findings a full scan surfaced two
// days ago, and vice versa.
async function executeMonitoringPass(
  profile: MonitoredProfile,
  triggerSource: TriggerSource,
  // Injectable for tests, and the seam that makes adding a collector a registry
  // entry rather than an edit to this function.
  collectors: readonly CollectorSpec[],
  commit?: ProviderCommit,
): Promise<{ newFindings: Finding[]; writesSucceeded: boolean }> {
  const admin = getSupabaseAdmin();
  const anonKey = profile.monitored_anon_key_encrypted
    ? decrypt(profile.monitored_anon_key_encrypted)
    : null;

  const { data: lastSnapshot } = await admin
    .from("monitoring_snapshots")
    .select("findings")
    .eq("user_id", profile.id)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const previousFindings = (lastSnapshot?.findings ?? []) as Finding[];

  const { results, outcomes } = await runCollectors(collectors, {
    profile,
    anonKey,
    triggerSource,
    previousFindings,
    commit,
  });

  // Snapshot findings are the current state of everything checked this pass;
  // newFindings come from collectors that already diffed and persisted their own
  // (see CollectorResult's doc comment for why both exist).
  const currentFindings: Finding[] = [];
  const preDiffedNewFindings: Finding[] = [];
  for (const result of results) {
    if (result.snapshotFindings) currentFindings.push(...result.snapshotFindings);
    if (result.newFindings) preDiffedNewFindings.push(...result.newFindings);
    if (result.facts) {
      await saveFacts(profile.id, result.facts.collector, result.facts.facts, {
        merge: result.facts.merge,
      });
    }
  }

  // A pass where every snapshot-producing collector failed must not write an
  // empty CURRENT state: that would read as "everything got fixed" and make
  // every real finding look new again on recovery. Carrying the prior state
  // forward preserves finding truth while still appending the collector
  // outcomes, so a failed/unread pass is visible rather than disappearing.
  const snapshotProduced = results.some((r) => r.snapshotFindings !== undefined);
  const { newFindings } = snapshotProduced
    ? diffSnapshots(previousFindings, currentFindings)
    : { newFindings: [] as Finding[] };
  let writesSucceeded = true;
  try {
    const snapshotWrite = await admin
      .from("monitoring_snapshots")
      .insert({
        user_id: profile.id,
        trigger_source: triggerSource,
        findings: snapshotProduced ? currentFindings : previousFindings,
        // Which collectors ran, and how they fared. This is the per-pass record
        // that makes the finding history reconstructable later: without it a
        // snapshot cannot distinguish "this layer reported clean" from "this
        // layer never ran", and those mean opposite things.
        collectors: outcomes,
      });
    if (snapshotWrite.error) writesSucceeded = false;
  } catch {
    writesSucceeded = false;
  }

  // Only full scans count toward "when was this user last actually checked" for
  // the 48h staleness filter in /api/monitor/scheduled. If the hourly pass
  // refreshed this too, a user with hourly monitoring enabled would never look
  // stale enough for the full scan to run again — the hourly cron ticks far more
  // often than 48h and would keep the timestamp perpetually fresh.
  const collectedAnything = outcomes.some((outcome) => outcome.status === "ok");
  if (triggerSource !== "hourly" && collectedAnything) {
    try {
      const cursorWrite = await admin
        .from("user_profiles")
        .update({ last_monitored_at: new Date().toISOString() })
        .eq("id", profile.id);
      if (cursorWrite.error) writesSucceeded = false;
    } catch {
      writesSucceeded = false;
    }
  }

  // Both lanes, deduplicated by id. The worker admits one durable
  // notification job for them; this pass never sends email itself.
  const allNewFindings = [...new Map(
    [...newFindings, ...preDiffedNewFindings].map((finding) => [finding.id, finding]),
  ).values()];
  return { newFindings: allNewFindings, writesSucceeded };
}

/** The monitor worker's pass. Provider collectors write only through `commit`
 * (3F-C2c); a pass without one cannot collect provider evidence. */
export function runMonitoringPassForWorker(
  profile: MonitoredProfile,
  triggerSource: TriggerSource,
  collectors: readonly CollectorSpec[] = DEFAULT_COLLECTORS,
  commit?: ProviderCommit,
) {
  return executeMonitoringPass(profile,triggerSource,collectors,commit);
}
