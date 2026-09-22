import { NextResponse } from "next/server";
import { admitDueRepositoryAudits } from "@/lib/jobs/scheduler";
import { isAuthorizedWorkerRequest } from "@/lib/jobs/workerAuth";

export const maxDuration = 30;

/** Admit one bounded batch. The worker repeats while `limited` is true; no
 * repository, credential, or tenant detail leaves this endpoint. */
export async function POST(request: Request) {
  if (!isAuthorizedWorkerRequest(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const result = await admitDueRepositoryAudits(new Date(), 1_000);
    return NextResponse.json({
      admitted: result.admitted,
      failed: result.failed,
      more: result.limited,
    });
  } catch {
    console.error("[jobs/schedule] admission failed");
    return NextResponse.json({ error: "Scheduler invocation failed." }, { status: 500 });
  }
}
