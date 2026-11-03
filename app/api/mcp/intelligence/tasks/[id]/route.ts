import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { getIntelligenceTask } from "@/lib/intelligence/tasks";

/** A customer's host reads one of its own intelligence tasks:
 * repository, commit, instruction, paths and hashes, never source. */
export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await authMcp(req);
  if ("error" in auth) return auth.error;
  const id = z.uuid().safeParse((await params).id);
  if (!id.success) return NextResponse.json({ error: "invalid_task" }, { status: 400 });
  const task = await getIntelligenceTask(auth.userId, id.data).catch(() => undefined);
  if (task === undefined) return NextResponse.json({ error: "task_unreadable" }, { status: 503 });
  if (!task) return NextResponse.json({ error: "task_unavailable" }, { status: 404 });
  return NextResponse.json(task, { headers: { "Cache-Control": "no-store" } });
}
