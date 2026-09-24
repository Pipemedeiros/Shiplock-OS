import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * One receipt per model call (Q10 / Step 12B, migration 092): who it was for,
 * why, who paid, the model and token counts. Never prompt or output text.
 * Fail-soft: a lost receipt is logged and never fails the run it measures.
 */
export type UsagePurpose = "first_scan" | "customer_api" | "narrative" | "scan_report" | "proving";

export async function recordModelUsage(input: {
  userId: string; purpose: UsagePurpose; model: string; stopReason: string | null;
  usage: { input_tokens: number; output_tokens: number; cache_read_input_tokens?: number | null };
  auditRunId?: string | null; intelligenceTaskId?: string | null;
}): Promise<void> {
  try {
    const { error } = await getSupabaseAdmin().from("model_usage_receipts").insert({
      user_id: input.userId, purpose: input.purpose,
      funded_by: input.purpose === "customer_api" ? "customer" : "shiplock",
      model: input.model.slice(0, 100), input_tokens: input.usage.input_tokens, output_tokens: input.usage.output_tokens,
      cache_read_tokens: input.usage.cache_read_input_tokens ?? null, stop_reason: input.stopReason?.slice(0, 40) ?? null,
      audit_run_id: input.auditRunId ?? null, intelligence_task_id: input.intelligenceTaskId ?? null,
    });
    if (error) console.error(`[cost] usage receipt not stored (${input.purpose})`);
  } catch {
    console.error(`[cost] usage receipt not stored (${input.purpose})`);
  }
}
