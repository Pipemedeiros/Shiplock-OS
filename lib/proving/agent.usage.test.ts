import { beforeEach, expect, it, vi } from "vitest";
const m = vi.hoisted(() => ({ create: vi.fn(), record: vi.fn() }));
vi.mock("@anthropic-ai/sdk", () => ({ default: class { messages = { create: m.create }; } }));
vi.mock("@/lib/cost/modelUsage", () => ({ recordModelUsage: m.record }));
import { claudeProposer } from "./agent";
const context = { schema: "proving_x", table: "orders", columns: ["owner_id"], policies: [] };
beforeEach(() => { vi.clearAllMocks(); m.record.mockResolvedValue(undefined); });
it.each(["end_turn", "max_tokens"])("receipts every returned response even %s with malformed text", async stop_reason => {
  m.create.mockResolvedValue({ model: "test-model", usage: { input_tokens: 20, output_tokens: 10, cache_read_input_tokens: 3 }, stop_reason, content: [{ type: "text", text: "not json" }] });
  await claudeProposer("owner")(context, []);
  expect(m.record).toHaveBeenCalledExactlyOnceWith({ userId: "owner", purpose: "proving", model: "test-model", stopReason: stop_reason, usage: { input_tokens: 20, output_tokens: 10, cache_read_input_tokens: 3 } });
});
it("does not invent usage for an unsuccessful call", async () => {
  m.create.mockRejectedValue(new Error("offline"));
  expect(await claudeProposer("owner")(context, [])).toEqual([]);
  expect(m.record).not.toHaveBeenCalled();
});
