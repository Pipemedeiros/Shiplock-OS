import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

/** The customer's standing approval for their own intelligence host (10B-2b,
 * migration 076): which host, when ShipLock may ask it for work, and within
 * what token budgets. Proposals only; it never carries PR, merge, or deploy
 * authority, so every PR still needs its own click. No credential is stored. */
export const ConnectionApproval = z.strictObject({
  host: z.enum(["claude-code", "codex", "chatgpt", "api"]),
  deepScan: z.enum(["weekly", "off"]),
  prScan: z.enum(["every_pr", "every_2_days", "daily", "off"]),
  runTokenBudget: z.number().int().min(1000).max(1_000_000),
  monthlyTokenBudget: z.number().int().min(1000).max(50_000_000),
  allowProposals: z.literal(true),
}).refine((a) => a.monthlyTokenBudget >= a.runTokenBudget, { message: "Monthly budget must cover one run." });
export type ConnectionApproval = z.infer<typeof ConnectionApproval>;

const row = z.object({
  host: ConnectionApproval.shape.host, deep_scan_cadence: ConnectionApproval.shape.deepScan,
  pr_scan_cadence: ConnectionApproval.shape.prScan, run_token_budget: z.number(), monthly_token_budget: z.number(),
  approved_at: z.string(), revoked_at: z.string().nullable(),
});

export type ConnectionView =
  | { state: "none" }
  | { state: "approved" | "revoked"; host: ConnectionApproval["host"]; deepScan: ConnectionApproval["deepScan"];
      prScan: ConnectionApproval["prScan"]; runTokenBudget: number; monthlyTokenBudget: number; approvedAt: string;
      // A pull host spends its own allowance, so ShipLock can only ask it to
      // stay within budget. API-key mode caps each call and counts the API's
      // own usage against the monthly limit (10B-2e).
      budgetEnforcement: "advisory" | "enforced"; pullRequests: "each_needs_a_click";
      // Tokens the host reported on results this UTC month. Self-reported, not
      // verified; new tasks stop once it reaches the monthly budget.
      monthReportedTokens: number };

export async function getIntelligenceConnection(userId: string): Promise<ConnectionView> {
  const { data, error } = await getSupabaseAdmin().from("intelligence_connections")
    .select("host,deep_scan_cadence,pr_scan_cadence,run_token_budget,monthly_token_budget,approved_at,revoked_at")
    .eq("user_id", userId).maybeSingle();
  if (error) throw new Error("connection_unreadable");
  if (!data) return { state: "none" };
  const r = row.parse(data);
  const usage = await getSupabaseAdmin().rpc("intelligence_month_usage", { p_user: userId });
  const reported = z.coerce.number().int().nonnegative().safeParse(usage.data);
  if (usage.error || !reported.success) throw new Error("connection_unreadable");
  return { state: r.revoked_at ? "revoked" : "approved", host: r.host, deepScan: r.deep_scan_cadence,
    prScan: r.pr_scan_cadence, runTokenBudget: r.run_token_budget, monthlyTokenBudget: r.monthly_token_budget,
    approvedAt: r.approved_at, budgetEnforcement: r.host === "api" ? "enforced" : "advisory",
    pullRequests: "each_needs_a_click", monthReportedTokens: reported.data };
}

export async function approveIntelligenceConnection(userId: string, approval: ConnectionApproval): Promise<void> {
  const { error } = await getSupabaseAdmin().rpc("approve_intelligence_connection", { p_user: userId,
    p_host: approval.host, p_deep: approval.deepScan, p_pr: approval.prScan,
    p_run: approval.runTokenBudget, p_month: approval.monthlyTokenBudget });
  if (error) throw new Error("connection_unwritable");
}

export async function revokeIntelligenceConnection(userId: string): Promise<{ cancelledTasks: number }> {
  const { data, error } = await getSupabaseAdmin().rpc("revoke_intelligence_connection", { p_user: userId });
  const n = z.number().int().nonnegative().safeParse(data);
  if (error || !n.success) throw new Error("connection_unwritable");
  return { cancelledTasks: n.data };
}
