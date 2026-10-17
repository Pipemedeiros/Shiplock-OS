import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { authMcp } from "@/lib/mcpAuth";
import { getOpenFindings } from "@/lib/agent/dashboardData";
import { getSupabaseAdmin } from "@/lib/supabase";
import { readSelfCheck, reportedHost, selfCheck } from "@/lib/proof/selfCheck";

/**
 * MCP tool `report_self_check`: the customer's agent ran the one harmless
 * request ShipLock offers for a finding (lib/proof/selfCheck.ts) against a
 * local or preview app, and reports the status it got. ShipLock never sends
 * the request. The method and path stored are ShipLock's own, derived from
 * the finding; the agent supplies only the status and the host it used, and
 * the founder's production address is refused (production is never
 * attacked). The report is untrusted agent output: shown as "test ran,
 * reported by your agent", never proof, never a status (migration 107).
 */
const Body = z.object({
  findingId: z.string().min(1).max(400),
  repository: z.string().min(1).max(200).optional(),
  status: z.number().int().min(100).max(599),
  host: z.string().min(1).max(300),
});
const bad = (error: string, status = 400) => NextResponse.json({ error }, { status });

export async function POST(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;
  const parsed = Body.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return bad("Send findingId, the integer status you got, and the host you ran it against.");
  const host = reportedHost(parsed.data.host);
  if (!host) return bad("Send the host you ran it against, like localhost:3000 or your preview's address.");

  const admin = getSupabaseAdmin();
  const { data: profile } = await admin.from("user_profiles").select("monitored_app_url").eq("id", ctx.userId).maybeSingle();
  const production = typeof profile?.monitored_app_url === "string" ? reportedHost(profile.monitored_app_url) : null;
  if (production && host === production) {
    return bad("That is the customer's production address. Run the check on a local or preview app, never production.");
  }

  const matches = (await getOpenFindings(ctx.userId)).filter((f) => f.id === parsed.data.findingId
    && (!parsed.data.repository || f.repository === parsed.data.repository));
  if (matches.length === 0) return bad("No such open finding.", 404);
  if (matches.length > 1) return bad("That id is open in more than one repository; pass repository as owner/name.", 409);
  const finding = matches[0];
  const check = finding.entry ? selfCheck({ entry: finding.entry, attackClass: finding.attackClass }) : null;
  if (!check) return bad("This finding has no one-request self-check.", 409);

  const { error } = await admin.rpc("record_self_check", { p_user: ctx.userId, p_finding_row: finding.rowId,
    p_method: check.method, p_path: check.path, p_status: parsed.data.status, p_host: host });
  if (error) return bad("Could not record the report. Try again.", 503);
  const { outcome, meaning } = readSelfCheck(parsed.data.status);
  return NextResponse.json({ recorded: true, request: `${check.method} ${check.path}`, outcome, meaning,
    next: "Recorded as a test your agent ran, not proof. Tell the customer what you saw; ShipLock shows it on the finding." });
}
