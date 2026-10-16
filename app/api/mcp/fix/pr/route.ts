import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { AGENT_PRS_OFF, requestAgentRepairAction } from "@/lib/jobs/repairAction";
import { quotaResponse } from "@/lib/quota";

/**
 * MCP tool `open_fix_pull_request`: the customer's own agent asks for the
 * same fix PR the Risks-board click opens (103, Felipe 2026-10-15). Refused
 * unless the customer turned agent pull requests on for that repository in
 * the dashboard (lib/agentPrs.ts). The finding and its change are resolved
 * from ShipLock's records exactly as for a click; the agent supplies no
 * content. The PR opens on a new branch through the receipted repair worker
 * and ShipLock never merges.
 */
const Body = z.object({ findingId: z.string().min(1).max(400) });

const OFF =
  "Agent pull requests are off for this repository. The customer turns them on in ShipLock, Settings, Agent pull requests, after reading the risks. Until then, make the change in your own checkout and open the pull request yourself, or ask the customer to open it from the finding.";

export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Name a finding id from get_security_context." }, { status: 400 });

  const resolved = await resolveRepairTarget(ctx.userId, { lane: "risk", findingId: parsed.data.findingId });
  if (!resolved.ok) {
    if (resolved.code === "not_found") return NextResponse.json({ error: "No such open finding." }, { status: 404 });
    if (resolved.code === "manual") {
      return NextResponse.json({ error: "This finding is a decision about who may see what, so ShipLock opens no pull request for it. Tell the customer what you would change and why." }, { status: 409 });
    }
    if (resolved.code === "already_open") return NextResponse.json({ url: resolved.url, alreadyOpen: true });
    return NextResponse.json({ error: "The customer has to select this repository again in ShipLock." }, { status: 409 });
  }

  try {
    const receiptId = await requestAgentRepairAction({
      userId: ctx.userId, repositoryId: resolved.target.repositoryId, findingId: resolved.target.findingId!,
    });
    return NextResponse.json({
      receiptId, status: "queued",
      next: "Call get_fix_pull_request with this receiptId until it is opened, then ask the customer to review it. ShipLock never merges.",
    }, { status: 202 });
  } catch (err) {
    if (err instanceof Error && err.message === AGENT_PRS_OFF) return NextResponse.json({ error: OFF }, { status: 403 });
    const quota = quotaResponse(err);
    if (quota) return quota;
    return NextResponse.json({ error: "Could not queue the pull request. Try again." }, { status: 503 });
  }
}
