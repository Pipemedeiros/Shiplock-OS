import { NextRequest, NextResponse } from "next/server";
import { admitDueMonitoringPasses } from "@/lib/jobs/scheduler";

// No trigger is configured today. If the hourly wake is restored, this route
// only admits bounded identity-only work; provider calls run in leased workers.
export const maxDuration = 30;

export async function GET(req: NextRequest) {
  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  try {
    const admission = await admitDueMonitoringPasses("hourly", new Date(), 1_000);
    return NextResponse.json({
      checked: admission.eligible,
      succeeded: admission.admitted,
      failed: admission.failed,
      deferred: admission.limited,
    });
  } catch {
    console.error("[monitor/hourly] admission failed");
    return NextResponse.json({ error: "Monitoring could not be queued." }, { status: 503 });
  }
}
