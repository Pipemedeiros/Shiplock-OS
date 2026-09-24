import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

/**
 * Starts one authorized proof (Q7 / Step 6A-3). The customer's click first
 * issued a per-test authorization (/api/proving/authorize, Q5); this consumes
 * it and queues one `proof` job in one transaction (enqueue_proof_job, 091).
 * The SQL function refuses an authorization that is not the caller's, has
 * expired, or was already used. The proof runs later, in the worker, on
 * ShipLock's own disposable replica with synthetic rows.
 */
const Body = z.strictObject({ authorizationId: z.uuid() });
const noStore = { headers: { "Cache-Control": "no-store" } };

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  let input;
  try { input = Body.parse(await request.json()); }
  catch { return NextResponse.json({ error: "Invalid request." }, { status: 400 }); }
  const { data, error } = await getSupabaseAdmin().rpc("enqueue_proof_job", {
    p_user: pro.userId, p_authorization: input.authorizationId,
  });
  if (error) {
    if (error.message.includes("proof authorization unavailable")) {
      return NextResponse.json({ error: "That test is no longer available. Start it again." }, { status: 404 });
    }
    return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  }
  const jobId = z.uuid().safeParse(data);
  if (!jobId.success) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  return NextResponse.json({ jobId: jobId.data }, noStore);
}
