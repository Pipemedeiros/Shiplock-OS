import { beforeEach, describe, expect, it, vi } from "vitest";

const insert = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => ({ insert: (row: unknown) => insert(table, row) }) }) }));

import { recordModelUsage } from "./modelUsage";

beforeEach(() => { insert.mockReset().mockResolvedValue({ error: null }); });

describe("recordModelUsage (Q10 / 12B)", () => {
  it("stores one receipt with counts only", async () => {
    await recordModelUsage({ userId: "u1", purpose: "first_scan", auditRunId: "r1", model: "claude-haiku-4-5",
      usage: { input_tokens: 1200, output_tokens: 300, cache_read_input_tokens: 0 }, stopReason: "max_tokens" });
    expect(insert).toHaveBeenCalledWith("model_usage_receipts", { user_id: "u1", purpose: "first_scan", funded_by: "shiplock",
      model: "claude-haiku-4-5", input_tokens: 1200, output_tokens: 300, cache_read_tokens: 0, stop_reason: "max_tokens",
      audit_run_id: "r1", intelligence_task_id: null });
  });
  it("marks customer API usage as customer funded", async () => {
    await recordModelUsage({ userId: "u1", purpose: "customer_api", intelligenceTaskId: "t1", model: "m", usage: { input_tokens: 1, output_tokens: 2 }, stopReason: null });
    expect(insert.mock.calls[0][1]).toMatchObject({ funded_by: "customer", intelligence_task_id: "t1", audit_run_id: null, cache_read_tokens: null });
  });
  it("never throws: a lost receipt must not fail the run", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    insert.mockResolvedValue({ error: { message: "down" } });
    await expect(recordModelUsage({ userId: "u1", purpose: "narrative", model: "m", usage: { input_tokens: 1, output_tokens: 1 }, stopReason: null })).resolves.toBeUndefined();
    insert.mockRejectedValue(new Error("network"));
    await expect(recordModelUsage({ userId: "u1", purpose: "narrative", model: "m", usage: { input_tokens: 1, output_tokens: 1 }, stopReason: null })).resolves.toBeUndefined();
    log.mockRestore();
  });
});
