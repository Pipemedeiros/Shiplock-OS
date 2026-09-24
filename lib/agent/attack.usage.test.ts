import { afterEach, describe, expect, it, vi } from "vitest";

// Q10: every model response's usage comes back with the outcome, so the audit
// can record a receipt, including a truncated answer.
const create = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic { messages = { create }; static APIConnectionTimeoutError = class extends Error {}; }
  return { default: Anthropic };
});

import { proposeAttacks } from "./attack";
import type { RouteFact } from "@/lib/graph/routeInventory";

const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: false,
  machineGated: false, ownershipFiltered: false, usesServiceRole: false, via: [], identityReadable: true, identityGap: null,
  ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null } as unknown as RouteFact;
const input = { routes: [route], stack: { tools: [] } as never, tables: ["orders"], files: ["app/api/orders/route.ts"] };

afterEach(() => { vi.unstubAllEnvs(); create.mockReset(); });

describe("proposeAttacks usage (Q10)", () => {
  it.each([["end_turn", "[]"], ["max_tokens", "[{\"class\":"]])("returns usage with stop reason %s", async (stop, text) => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue({ content: [{ type: "text", text }], stop_reason: stop,
      usage: { input_tokens: 900, output_tokens: 120, cache_read_input_tokens: 0 } });
    const outcome = await proposeAttacks(input);
    expect(outcome.usage).toEqual({ model: expect.any(String), input_tokens: 900, output_tokens: 120, cache_read_input_tokens: 0, stopReason: stop });
  });
  it("returns no usage when the call failed", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockRejectedValue(new Error("boom"));
    expect((await proposeAttacks(input)).usage).toBeUndefined();
  });
});
