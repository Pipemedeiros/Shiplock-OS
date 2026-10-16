import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";
import { AGENT_PRS_ACK } from "@/lib/agentPrs";

/**
 * The customer turns agent pull requests on or off for one repository (103,
 * lib/agentPrs.ts). Cookie session on ShipLock's own page only: a token, and
 * so an agent, can never grant itself this right.
 */
const On = z.object({ repositoryId: z.uuid(), acknowledgement: z.literal(AGENT_PRS_ACK) });
const Off = z.object({ repositoryId: z.uuid() });

async function change(request: Request, on: boolean) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const parsed = (on ? On : Off).safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: on ? "Read and accept the risks first." : "Name a repository." }, { status: 400 });
  }
  const { error } = await getSupabaseAdmin().rpc(on ? "grant_agent_prs" : "revoke_agent_prs", on
    ? { p_user: user.userId, p_repository: parsed.data.repositoryId, p_ack: AGENT_PRS_ACK }
    : { p_user: user.userId, p_repository: parsed.data.repositoryId });
  if (error) {
    if (/repository unavailable/.test(error.message)) return NextResponse.json({ error: "Select this repository first." }, { status: 409 });
    return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  }
  return NextResponse.json({ on });
}

export const POST = (request: Request) => change(request, true);
export const DELETE = (request: Request) => change(request, false);
