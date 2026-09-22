import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";

// A PAT cannot bypass the durable scan queue. Restore this action only with
// scoped admission, retry/fencing, and an explicit customer authorization.
export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;
  return NextResponse.json({ error: "Start a scan from the ShipLock dashboard." }, { status: 403 });
}
