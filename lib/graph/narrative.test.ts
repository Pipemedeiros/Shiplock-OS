import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AttackPath } from "./attackPaths";

// The model path, with the API mocked. Proves the two properties that matter:
// the guard is actually applied to real model output, and every failure mode
// falls back to the deterministic template rather than to a blank finding.

const createMock = vi.fn();
vi.mock("@anthropic-ai/sdk", () => ({
  default: class {
    messages = { create: createMock };
  },
}));

const { generateNarratives } = await import("./narrative");

function path(over: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "path:anon_route_unprotected_table",
    severity: "CRITICAL",
    title: "Orders table readable across tenants",
    consequence: "Template wording.",
    evidence: [
      { collector: "source", fact: "/api/orders resolves no user identity" },
      { collector: "db", fact: "public.orders has no RLS policy" },
    ],
    score: 9,
    surfaces: ["source", "db"],
    ...over,
  };
}

function reply(body: unknown, usage = { input_tokens: 400, output_tokens: 120 }) {
  return {
    content: [{ type: "text", text: JSON.stringify(body) }],
    usage,
  };
}

describe("generateNarratives", () => {
  beforeEach(() => {
    createMock.mockReset();
    process.env.ANTHROPIC_API_KEY = "sk-ant-test";
    process.env.SHIPLOCK_FUNDED_NARRATIVES = "true";
  });

  it("spends nothing unless ShipLock-funded narratives are explicitly on (3G-2)", async () => {
    delete process.env.SHIPLOCK_FUNDED_NARRATIVES;
    const result = await generateNarratives([path()]);
    expect(createMock).not.toHaveBeenCalled();
    expect(result.accepted.size).toBe(0);
  });

  it("reports the model and usage of a call so it can be receipted (Q10)", async () => {
    createMock.mockResolvedValue(reply({ narratives: [] }));
    const result = await generateNarratives([path()]);
    expect(result).toMatchObject({ model: "claude-haiku-4-5-20251001", tokensIn: 400, tokensOut: 120 });
    delete process.env.SHIPLOCK_FUNDED_NARRATIVES;
    expect((await generateNarratives([path()])).model).toBeUndefined();
  });

  it("accepts a grounded narrative", async () => {
    createMock.mockResolvedValue(
      reply({
        narratives: [
          {
            id: "path:anon_route_unprotected_table",
            narrative: "Nothing between the caller and the table checks who is asking.",
            citedFacts: ["public.orders has no RLS policy"],
          },
        ],
      })
    );

    const result = await generateNarratives([path()]);

    expect(result.accepted.get("path:anon_route_unprotected_table")).toBe(
      "Nothing between the caller and the table checks who is asking."
    );
    expect(result.rejected).toHaveLength(0);
  });

  it("rejects a hallucinated fact and keeps nothing, so the template survives", async () => {
    createMock.mockResolvedValue(
      reply({
        narratives: [
          {
            id: "path:anon_route_unprotected_table",
            narrative: "Your admin dashboard is also wide open.",
            citedFacts: ["/api/admin has no auth check"],
          },
        ],
      })
    );

    const result = await generateNarratives([path()]);

    expect(result.accepted.size).toBe(0);
    expect(result.rejected[0].reason).toMatch(/never collected/);
  });

  it("rejects an escalated breach claim even when the cited fact is real", async () => {
    createMock.mockResolvedValue(
      reply({
        narratives: [
          {
            id: "path:anon_route_unprotected_table",
            narrative: "Customer records have been exfiltrated through this route.",
            citedFacts: ["public.orders has no RLS policy"],
          },
        ],
      })
    );

    const result = await generateNarratives([path()]);
    expect(result.accepted.size).toBe(0);
  });

  it("rejects a narrative for an id we never sent", async () => {
    createMock.mockResolvedValue(
      reply({
        narratives: [
          { id: "path:invented", narrative: "Something else is wrong.", citedFacts: [] },
        ],
      })
    );

    const result = await generateNarratives([path()]);
    expect(result.accepted.size).toBe(0);
    expect(result.rejected[0].reason).toMatch(/unknown finding id/);
  });

  it("returns empty on an API error rather than failing the pass", async () => {
    createMock.mockRejectedValue(new Error("529 overloaded"));
    const result = await generateNarratives([path()]);
    expect(result.accepted.size).toBe(0);
    expect(result.tokensIn).toBe(0);
  });

  it("returns empty on unparseable output", async () => {
    createMock.mockResolvedValue({
      content: [{ type: "text", text: "I'm sorry, I can't do that." }],
      usage: { input_tokens: 10, output_tokens: 5 },
    });
    const result = await generateNarratives([path()]);
    expect(result.accepted.size).toBe(0);
  });

  it("tolerates a prose wrapper around the JSON rather than dropping the batch", async () => {
    createMock.mockResolvedValue({
      content: [
        {
          type: "text",
          text:
            'Here you go:\n{"narratives":[{"id":"path:anon_route_unprotected_table","narrative":"Any caller reads every tenant\'s rows.","citedFacts":["public.orders has no RLS policy"]}]}\nHope that helps!',
        },
      ],
      usage: { input_tokens: 400, output_tokens: 120 },
    });

    const result = await generateNarratives([path()]);
    expect(result.accepted.size).toBe(1);
  });

  it("makes no call at all when there are no new findings", async () => {
    const result = await generateNarratives([]);
    expect(createMock).not.toHaveBeenCalled();
    expect(result.accepted.size).toBe(0);
  });

  it("makes one call for a batch, not one per finding", async () => {
    createMock.mockResolvedValue(reply({ narratives: [] }));

    await generateNarratives([
      path({ id: "path:a" }),
      path({ id: "path:b" }),
      path({ id: "path:c" }),
    ]);

    expect(createMock).toHaveBeenCalledTimes(1);
  });

  it("caps how many findings go into one prompt", async () => {
    createMock.mockResolvedValue(reply({ narratives: [] }));

    const many = Array.from({ length: 20 }, (_, i) => path({ id: `path:${i}` }));
    await generateNarratives(many);

    const prompt = createMock.mock.calls[0][0].messages[0].content as string;
    expect(prompt).toContain("path:5");
    expect(prompt).not.toContain("path:6");
  });

  it("uses Haiku by default, per the token-efficiency doctrine", async () => {
    createMock.mockResolvedValue(reply({ narratives: [] }));
    await generateNarratives([path()]);
    expect(createMock.mock.calls[0][0].model).toBe("claude-haiku-4-5-20251001");
  });
});
