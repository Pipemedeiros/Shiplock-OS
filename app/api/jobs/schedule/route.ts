import { NextResponse } from "next/server";
import {
  admitDueRepositoryAudits,
  admitDueRepositoryDependencyChecks,
  admitDueRepositorySourceScans,
} from "@/lib/jobs/scheduler";
import { isAuthorizedWorkerRequest } from "@/lib/jobs/workerAuth";

export const maxDuration = 30;

/** Admit one bounded batch. The worker repeats while `limited` is true; no
 * repository, credential, or tenant detail leaves this endpoint. */
export async function POST(request: Request) {
  if (!isAuthorizedWorkerRequest(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const now = new Date();
    const [audits, sources, dependencies] = await Promise.all([
      admitDueRepositoryAudits(now, 1_000),
      admitDueRepositorySourceScans(now, 1_000),
      admitDueRepositoryDependencyChecks(now, 1_000),
    ]);
    return NextResponse.json({
      admitted: audits.admitted + sources.admitted + dependencies.admitted,
      failed: audits.failed + sources.failed + dependencies.failed,
      more: audits.limited || sources.limited || dependencies.limited,
    });
  } catch {
    console.error("[jobs/schedule] admission failed");
    return NextResponse.json({ error: "Scheduler invocation failed." }, { status: 500 });
  }
}
