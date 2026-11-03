import { afterEach, describe, expect, it, vi } from "vitest";

// The developer corpus harness's model calls (scripts/corpusModel.ts). No
// provider request is made: the SDK is mocked.
const create = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic { messages = { create }; static APIConnectionTimeoutError = class extends Error {}; }
  return { default: Anthropic };
});

import { maxTokensFor, PROPOSE_MODEL, proposeAttacks, THINKING_HEADROOM, VERIFY_MODEL, verifyAttacks } from "./corpusModel";
import type { RouteFact } from "@/lib/graph/routeInventory";

const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: false,
  machineGated: false, ownershipFiltered: false, usesServiceRole: false, via: [], identityReadable: true, identityGap: null,
  ownershipReadable: true, ownershipGap: null, serviceRoleReadable: true, machineGateReadable: true, machineGateGap: null } as unknown as RouteFact;
const input = { routes: [route], stack: { tools: [] } as never, tables: ["orders"], files: ["app/api/orders/route.ts"] };
const ok = { content: [{ type: "text", text: "[]" }], stop_reason: "end_turn", usage: { input_tokens: 10, output_tokens: 2, cache_read_input_tokens: 0 } };

afterEach(() => { vi.unstubAllEnvs(); create.mockReset(); });

describe("corpus proposing call", () => {
  it("sends one top-model request with room to think and no sampling parameters", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue(ok);
    await proposeAttacks(input);
    const request = create.mock.calls[0][0];
    expect(request.model).toBe(PROPOSE_MODEL);
    expect(PROPOSE_MODEL).toBe("claude-opus-5-5");
    expect(request).not.toHaveProperty("temperature");
    expect(request).not.toHaveProperty("thinking");
    expect(request.output_config).toEqual({ effort: "medium" });
    expect(request.max_tokens).toBe(maxTokensFor(1) + THINKING_HEADROOM);
  });

  it("with claude-sonnet-5 sends no temperature and disables thinking", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue(ok);
    const outcome = await proposeAttacks({ ...input, model: "claude-sonnet-5" });
    const request = create.mock.calls[0][0];
    expect(request.thinking).toEqual({ type: "disabled" });
    expect(request).not.toHaveProperty("temperature");
    expect(outcome.usage?.model).toBe("claude-sonnet-5");
  });

  it("refuses an override that is not on the test list, before any call", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    await expect(proposeAttacks({ ...input, model: "claude-opus-5-5" })).rejects.toThrow(/not an allowed test model/);
    expect(create).not.toHaveBeenCalled();
  });

  it.each([["end_turn", "[]"], ["max_tokens", "[{\"class\":"]])("returns usage with stop reason %s", async (stop, text) => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue({ content: [{ type: "text", text }], stop_reason: stop,
      usage: { input_tokens: 900, output_tokens: 120, cache_read_input_tokens: 0 } });
    expect((await proposeAttacks(input)).usage).toEqual({ model: expect.any(String), input_tokens: 900, output_tokens: 120,
      cache_read_input_tokens: 0, stopReason: stop });
  });

  it("keeps a transport failure a stated skip with no usage", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockRejectedValue(new Error("provider unavailable"));
    const outcome = await proposeAttacks(input);
    expect(outcome).toMatchObject({ skipped: true, skipReason: "model call failed: provider unavailable" });
    expect(outcome.usage).toBeUndefined();
  });

  it("budgets output for what it asked about, not a round number", () => {
    expect(maxTokensFor(60)).toBeGreaterThanOrEqual(60 * 200);
    expect(maxTokensFor(1)).toBeGreaterThanOrEqual(4000);
    expect(maxTokensFor(10000)).toBeLessThanOrEqual(16000);
  });
});

describe("corpus verifier call", () => {
  const file = "app/api/orders/route.ts";
  const files = new Map([[file, "export async function GET() {\n  return Response.json(await db.from(\"orders\").select(\"*\"));\n}"]]);
  const item = { id: "0", entry: "/api/orders", attackClass: "missing_authorization", title: "T", consequence: "c", citedFiles: [file], handlerFile: file };

  it("sends a structured-output request on a 5.5 model", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockResolvedValue({ content: [{ type: "text", text: JSON.stringify({ verdicts: [] }) }], stop_reason: "end_turn",
      usage: { input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 0 } });
    await verifyAttacks({ items: [item], files });
    const request = create.mock.calls[0][0];
    expect(request.model).toBe(VERIFY_MODEL);
    expect(VERIFY_MODEL).toMatch(/-5-5$/);
    expect(request.output_config.format.type).toBe("json_schema");
    expect(request).not.toHaveProperty("temperature");
  });

  it("verifies nothing when the call fails or there is no key", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockRejectedValue(new Error("boom"));
    expect((await verifyAttacks({ items: [item], files })).verdicts.map((v) => v.verdict)).toEqual(["unverified"]);
    vi.stubEnv("ANTHROPIC_API_KEY", "");
    expect((await verifyAttacks({ items: [item], files })).verdicts.map((v) => v.verdict)).toEqual(["unverified"]);
  });
});
