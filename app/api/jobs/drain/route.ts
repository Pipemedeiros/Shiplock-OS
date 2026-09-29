import { NextResponse } from "next/server";
import { runNextJob } from "@/lib/jobs/worker";
import { isAuthorizedWorkerRequest } from "@/lib/jobs/workerAuth";

// One audit owns the invocation budget. The independent caller repeats this
// bounded request; the route never holds an open polling loop.
export const maxDuration = 300;

export async function POST(request: Request) {
  if (!isAuthorizedWorkerRequest(request)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const claimed = await runNextJob();
    return NextResponse.json({ processed: claimed ? 1 : 0 });
  } catch {
    // A provider/storage error can contain tenant context. The job records its
    // bounded retry state; the wake surface logs no arbitrary error message.
    console.error("[jobs/drain] worker stopped");
    return NextResponse.json({ error: "Worker invocation failed." }, { status: 500 });
  }
}
