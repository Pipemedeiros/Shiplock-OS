import { runNextPullRequestCheckJob } from "./prCheckWorker";
import { runNextAuditJob } from "./auditWorker";
import { runNextSourceJob } from "./sourceWorker";
import { runNextGraphJob } from "./graphWorker";

/** One bounded unit per invocation. PR feedback is latency-sensitive; audits
 * remain available on the next cycle and each kind has its own SQL limit. */
export async function runNextJob(): Promise<boolean> {
  if (await runNextPullRequestCheckJob()) return true;
  if (await runNextAuditJob()) return true;
  if (await runNextGraphJob()) return true;
  return runNextSourceJob();
}
