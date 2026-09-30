import { afterEach, describe, expect, it, vi } from "vitest";

// P1: a proposal becomes a finding only after the skeptical verifier confirms
// it with quotes that exist in the code. Batches of VERIFY_BATCH, one usage
// receipt per call, and a failed call keeps everything out of the findings.
const create = vi.hoisted(() => vi.fn());
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic { messages = { create }; static APIConnectionTimeoutError = class extends Error {}; }
  return { default: Anthropic };
});

import { VERIFY_BATCH, VERIFY_MODEL, verifyAdmitted } from "./attack";

const file = "app/api/orders/route.ts";
const files = new Map([[file, "export async function GET() {\n  return Response.json(await db.from(\"orders\").select(\"*\"));\n}"]]);
const proposal = (i: number) => ({ entry: "/api/orders", attackClass: "missing_authorization", title: `T${i}`, consequence: "old", citedFiles: [file] });
const routes = [{ path: "/api/orders", file }];
const reply = (verdicts: unknown[]) => ({ content: [{ type: "text", text: JSON.stringify({ verdicts }) }], stop_reason: "end_turn",
  usage: { input_tokens: 1000, output_tokens: 200, cache_read_input_tokens: 0 } });
const confirmed = (id: string) => ({ id, verdict: "confirmed", severity: "critical", statement: "Anyone can read every order.", reason: "",
  citations: [{ role: "reach", path: file, line: 1, quote: "export async function GET() {" },
    { role: "data", path: file, line: 2, quote: "db.from(\"orders\").select(\"*\")" }] });

afterEach(() => { vi.unstubAllEnvs(); create.mockReset(); });

describe("verifyAdmitted (P1)", () => {
  it("keeps confirmed proposals only, in batches, with a structured-output request on a 5.5 model", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    const admitted = Array.from({ length: VERIFY_BATCH + 2 }, (_, i) => proposal(i));
    create.mockImplementation(async (request: { messages: { content: string }[] }) => {
      const ids = [...request.messages[0].content.matchAll(/"id": "(\d+)"/g)].map((m) => m[1]);
      return reply(ids.map((id) => (id === "0" ? confirmed(id) : { ...confirmed(id), verdict: "refuted", citations: [] })));
    });
    const out = await verifyAdmitted({ admitted, routes, files });
    expect(create).toHaveBeenCalledTimes(2);
    const request = create.mock.calls[0][0];
    expect(request.model).toBe(VERIFY_MODEL);
    expect(VERIFY_MODEL).toMatch(/-5-5$/);
    expect(request.output_config.format.type).toBe("json_schema");
    expect(request).not.toHaveProperty("temperature");
    expect(out.kept).toEqual([{ ...admitted[0], consequence: "Anyone can read every order." }]);
    expect(out.refuted).toBe(VERIFY_BATCH + 1);
    expect(out.usages).toHaveLength(2);
  });

  it("keeps nothing when the verifier fails or has no key", async () => {
    vi.stubEnv("ANTHROPIC_API_KEY", "test-key");
    create.mockRejectedValue(new Error("boom"));
    const failed = await verifyAdmitted({ admitted: [proposal(0)], routes, files });
    expect(failed).toMatchObject({ kept: [], unverified: 1, failed: true });
    vi.stubEnv("ANTHROPIC_API_KEY", "");
    expect((await verifyAdmitted({ admitted: [proposal(0)], routes, files })).kept).toEqual([]);
  });
});
