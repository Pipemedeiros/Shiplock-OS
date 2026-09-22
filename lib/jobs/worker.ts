import { runNextPullRequestCheckJob } from "./prCheckWorker";
import { runNextAuditJob } from "./auditWorker";
import { runNextSourceJob } from "./sourceWorker";
import { runNextGraphJob } from "./graphWorker";
import { runNextDependencyJob } from "./dependencyWorker";

/** One bounded unit per invocation. Customer-visible PR/audit work wins, then
 * already-admitted graph follow-ups, source refresh, and advisory rechecks.
 * Each kind has its own SQL concurrency limit. */
export async function runNextJob(): Promise<boolean> {
  if (await runNextPullRequestCheckJob()) return true;
  if (await runNextAuditJob()) return true;
  if (await runNextGraphJob()) return true;
  if (await runNextSourceJob()) return true;
  return runNextDependencyJob();
}
