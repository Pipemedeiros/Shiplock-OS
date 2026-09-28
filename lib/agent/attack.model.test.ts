import { afterEach, describe, expect, it, vi } from "vitest";

// Q13: a test-only model override for the corpus paid mode. Production never
// passes one, so its request is unchanged; Sonnet 5 rejects `temperature` and
// thinks by default, so its request drops sampling and disables thinking.
const create = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic { messages = { create }; static APIConnectionTimeoutError = class extends Error {}; }
  return { default: Anthropic };
});

import { HAIKU, proposeAttacks } from "./attack";
import type { RouteFact } from "@/lib/graph/routeInventory";

const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: false,
  machineGated: false, ownershipFiltered: false, usesServiceRole: false, via: [], identityReadable: true, identityGap: null,
  ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null } as unknown as RouteFact;
const input = { routes: [route], stack: { tools: [] } as never, tables: ["orders"], files: ["app/api/orders/route.ts"] };
const ok = { content: [{ type: "text", text: "[]" }], stop_reason: "end_turn", usage: { input_tokens: 10, output_tokens: 2, cache_read_input_tokens: 0 } };

afterEach(() => { vi.unstubAllEnvs(); create.mockReset(); });

describe("proposeAttacks model override (Q13)", () => {
  it("without an override sends production's request unchanged", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue(ok);
    await proposeAttacks(input);
    const request = create.mock.calls[0][0];
    expect(request.model).toBe(HAIKU);
    expect(request.temperature).toBe(0);
    expect(request).not.toHaveProperty("thinking");
  });

  it("with claude-sonnet-5 sends no temperature and disables thinking", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue(ok);
    const outcome = await proposeAttacks({ ...input, model: "claude-sonnet-5" });
    const request = create.mock.calls[0][0];
    expect(request.model).toBe("claude-sonnet-5");
    expect(request).not.toHaveProperty("temperature");
    expect(request.thinking).toEqual({ type: "disabled" });
    expect(outcome.usage?.model).toBe("claude-sonnet-5");
  });

  it("refuses an override that is not on the test list, before any call", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    await expect(proposeAttacks({ ...input, model: "claude-opus-5-5" })).rejects.toThrow(/not an allowed test model/);
    expect(create).not.toHaveBeenCalled();
  });
});
