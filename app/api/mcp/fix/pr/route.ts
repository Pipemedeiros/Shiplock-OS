import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";

// A PAT is not a separate customer approval to create a branch or PR. Restore
// this action only after it consumes the same approval receipt as the dashboard.
export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;
  return NextResponse.json({ error: "Approve and open the PR from the ShipLock dashboard." }, { status: 403 });
}
