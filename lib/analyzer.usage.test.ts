import { afterEach, describe, expect, it, vi } from "vitest";
import type { ScanResult } from "./scanner";

// Q10: the legacy scan report (flagged off in production) leaves a usage
// receipt for the account that ran it when it does call the model.
const create = vi.hoisted(() => vi.fn());
const receipt = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic {
    static APIError = class extends Error {}; static APIConnectionTimeoutError = class extends Error {};
    static AuthenticationError = class extends Error {}; static RateLimitError = class extends Error {};
    static InternalServerError = class extends Error {};
    messages = { create };
  }
  return { default: Anthropic };
});
vi.mock("@/lib/cost/modelUsage", () => ({ recordModelUsage: receipt }));

import { analyzeResult } from "./analyzer";

afterEach(() => { vi.unstubAllEnvs(); create.mockReset(); receipt.mockReset(); });

describe("analyzeResult usage receipt (Q10)", () => {
  it("records one scan_report receipt for the caller when the model answered", async () => {
    vi.stubEnv("SHIPLOCK_FUNDED_SCAN_REPORT", "true");
    create.mockResolvedValue({ content: [{ type: "text", text: "not json" }], stop_reason: "end_turn", usage: { input_tokens: 50, output_tokens: 7 } });
    await analyzeResult({ tables: [] } as unknown as ScanResult, "user-1");
    expect(receipt).toHaveBeenCalledTimes(1);
    expect(receipt.mock.calls[0][0]).toMatchObject({ userId: "user-1", purpose: "scan_report", usage: { input_tokens: 50, output_tokens: 7 } });
  });
  it("records nothing when the flag is off or no account is given", async () => {
    await analyzeResult({ tables: [] } as unknown as ScanResult, "user-1");
    vi.stubEnv("SHIPLOCK_FUNDED_SCAN_REPORT", "true");
    create.mockResolvedValue({ content: [{ type: "text", text: "x" }], stop_reason: "end_turn", usage: { input_tokens: 1, output_tokens: 1 } });
    await analyzeResult({ tables: [] } as unknown as ScanResult);
    expect(receipt).not.toHaveBeenCalled();
  });
});
