import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { previewRepair } from "@/lib/fixes/preview";
import { resolveRepairTarget } from "@/lib/fixes/repairTarget";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

/**
 * What a fix click would write, before the click. Read-only:
 * the lane runs with GitHub writes captured, no receipt, no job. POST because
 * a finding fix may carry the customer's edited content; it is guarded like a
 * mutation because it reads private repository code.
 */
const id = z.uuid();
const Body = z.discriminatedUnion("action", [
  z.strictObject({ action: z.literal("risk-fix-pr"), repositoryId: id, findingId: z.string().min(1).max(400) }),
  z.strictObject({ action: z.literal("finding-fix-pr"), repositoryId: id, findingId: z.string().min(1).max(400),
    editedContent: z.string().max(60_000).nullable().optional() }),
  z.strictObject({ action: z.literal("dependency-bump-pr"), repositoryId: id }),
  z.strictObject({ action: z.literal("pr-fix-pr"), repositoryId: id, findingId: z.string().min(1).max(400), reviewId: id }),
  z.strictObject({ action: z.literal("ai-fix-pr"), repositoryId: id, taskId: id }),
  z.strictObject({ action: z.literal("rate-limit-pr"), repositoryId: id, findingId: z.string().regex(/^traffic:\S{1,392}$/) }),
]);
// What the existing buttons know; the repository is resolved from our records.
const Button = z.discriminatedUnion("lane", [
  z.strictObject({ lane: z.literal("pull-request"), reviewId: id, findingId: z.string().min(1).max(400) }),
  z.strictObject({ lane: z.literal("ai"), taskId: id }),
  z.strictObject({ lane: z.literal("risk"), findingId: z.string().min(1).max(400) }),
  z.strictObject({ lane: z.literal("finding"), findingId: z.string().min(1).max(400), editedContent: z.string().max(60_000).nullable().optional() }),
]);

export async function POST(request: Request) {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const user = await requireProUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const raw = await request.json().catch(() => null);
  const parsed = Body.safeParse(raw);
  const button = parsed.success ? null : Button.safeParse(raw);
  if (!parsed.success && !button?.success) return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  try {
    const resolved = parsed.success ? { ok: true as const, target: parsed.data } : await resolveRepairTarget(user.userId, button!.data!);
    if (!resolved.ok) {
      if (resolved.code === "already_open") {
        return NextResponse.json({ status: "already_open", url: resolved.url }, { headers: { "Cache-Control": "no-store" } });
      }
      return NextResponse.json({ error: "There is no pull request to preview for this." }, { status: 404 });
    }
    return NextResponse.json(await previewRepair(user.userId, resolved.target), { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Could not build the preview. Try again." }, { status: 503 });
  }
}
