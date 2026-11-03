import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { listPendingIntelligenceTasks } from "@/lib/intelligence/tasks";

/** A customer's host polls for its pending intelligence tasks. */
export async function GET(req: NextRequest) {
  const auth = await authMcp(req);
  if ("error" in auth) return auth.error;
  try {
    const tasks = await listPendingIntelligenceTasks(auth.userId);
    return NextResponse.json({ tasks }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "tasks_unreadable" }, { status: 503 });
  }
}
