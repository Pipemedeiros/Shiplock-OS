import { runNextPullRequestCheckJob } from "./prCheckWorker";
import { runNextAuditJob } from "./auditWorker";

/** One bounded unit per invocation. PR feedback is latency-sensitive; audits
 * remain available on the next cycle and each kind has its own SQL limit. */
export async function runNextJob(): Promise<boolean> {
  if (await runNextPullRequestCheckJob()) return true;
  return runNextAuditJob();
}
