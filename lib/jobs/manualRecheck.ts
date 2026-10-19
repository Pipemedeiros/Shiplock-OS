import { after } from "next/server";
import { enqueueMonitoringPass } from "./scheduler";
import { runNextMonitorJob } from "./monitorWorker";
import { supersedeStaleScheduledJobs } from "./queue";

/**
 * A customer's "check now" (3F-C2c-5). Admits the same identity-only monitor
 * job a deploy would, labeled manual, instead of collecting inside the web
 * request. Repeated clicks for one transport within a minute share a job.
 * The wake is best effort; the queue owns retries and leases.
 */
export async function queueCustomerRecheck(userId: string, transport: string): Promise<string> {
  const minute = new Date().toISOString().slice(0, 16);
  const jobId = await enqueueMonitoringPass(userId, "manual", `manual:${transport}:${minute}`);
  after(async () => {
    // 108: drop stale scheduled copies first, so the wake does not land on one.
    try { await supersedeStaleScheduledJobs(); }
    catch { console.error("[recheck] stale scheduled jobs not superseded"); }
    try { await runNextMonitorJob(); }
    catch (err) { console.error("[recheck] queued worker stopped:", err instanceof Error ? err.message : "unknown error"); }
  });
  return jobId;
}
