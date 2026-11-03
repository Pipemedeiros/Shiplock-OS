import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { getSupabaseAdmin } from "@/lib/supabase";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

/**
 * One customer click authorizes one proof (migration 090):
 * one finding, one table, one selected repository, on ShipLock's disposable
 * replica only, for one hour. Nothing runs here; a proof job consumes it.
 */
const Body = z.strictObject({
  repositoryId: z.uuid(),
  findingId: z.string().min(1).max(1000),
  table: z.string().regex(/^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$/),
  key: z.string().min(1).max(200),
});
const noStore = { headers: { "Cache-Control": "no-store" } };

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  let input;
  try { input = Body.parse(await request.json()); }
  catch { return NextResponse.json({ error: "Invalid request." }, { status: 400 }); }
  const { data, error } = await getSupabaseAdmin().rpc("authorize_proof", {
    p_user: pro.userId, p_repository: input.repositoryId, p_finding: input.findingId, p_table: input.table, p_key: input.key,
  });
  if (error) {
    if (error.message.includes("idempotency key reused")) return NextResponse.json({ error: "That request was already used for a different test." }, { status: 409 });
    if (error.message.includes("repository unavailable")) return NextResponse.json({ error: "That repository is not selected." }, { status: 404 });
    if (error.message.includes("too many outstanding proofs")) return NextResponse.json({ error: "Five tests are already waiting. Let them finish first." }, { status: 429 });
    return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  }
  const id = z.uuid().safeParse(data);
  if (!id.success) return NextResponse.json({ error: "Try again in a moment." }, { status: 503 });
  return NextResponse.json({ authorizationId: id.data }, noStore);
}
