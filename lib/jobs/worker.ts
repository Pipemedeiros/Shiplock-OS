import { runNextPullRequestCheckJob } from "./prCheckWorker";
import { runNextAuditJob } from "./auditWorker";
import { runNextSourceJob } from "./sourceWorker";
import { runNextGraphJob } from "./graphWorker";
import { runNextDependencyJob } from "./dependencyWorker";
import { runNextMonitorJob } from "./monitorWorker";
import { runNextNotificationJob } from "./notificationWorker";
import { runNextRepairJob } from "./repairWorker";
import { runNextIntelligenceJob } from "./intelligenceWorker";

/** One bounded unit per invocation. Customer-visible PR/audit work wins, then
 * already-admitted graph follow-ups, source refresh, and advisory rechecks.
 * Each kind has its own SQL concurrency limit. */
export async function runNextJob(): Promise<boolean> {
  if (await runNextPullRequestCheckJob()) return true;
  if (await runNextNotificationJob()) return true;
  // A customer is waiting on a clicked repair; run it before background work.
  if (await runNextRepairJob()) return true;
  if (await runNextAuditJob()) return true;
  if (await runNextGraphJob()) return true;
  if (await runNextSourceJob()) return true;
  if (await runNextDependencyJob()) return true;
  // Creates a task for the customer's own AI; no model is called here.
  if (await runNextIntelligenceJob()) return true;
  return runNextMonitorJob();
}
