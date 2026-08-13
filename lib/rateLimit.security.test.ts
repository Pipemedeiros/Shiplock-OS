import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const countMock = vi.fn();
const insertMock = vi.fn();

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({ eq: () => ({ gte: countMock }) }),
      insert: insertMock,
    }),
  }),
}));

const { checkCheckoutRateLimit, getClientIpHash } = await import("./rateLimit");

function req(headers: Record<string, string> = {}) {
  return new NextRequest("https://shiplock.dev/api/checkout", { headers });
}

describe("checkCheckoutRateLimit — the limit must actually trigger under a burst, not just be configured", () => {
  beforeEach(() => {
    countMock.mockReset();
    insertMock.mockReset().mockResolvedValue({ error: null });
  });

  it("allows a request under the 5/hour threshold", async () => {
    countMock.mockResolvedValue({ count: 4, error: null });
    const result = await checkCheckoutRateLimit(req());
    expect(result.limited).toBe(false);
  });

  it("BLOCKS the 6th request within the window — a burst of 6 must not all succeed", async () => {
    countMock.mockResolvedValue({ count: 5, error: null });
    const result = await checkCheckoutRateLimit(req());
    expect(result.limited).toBe(true);
    if (result.limited) {
      expect(result.response.status).toBe(429);
    }
  });

  it("does not record a new attempt row when the caller is already over the limit", async () => {
    countMock.mockResolvedValue({ count: 10, error: null });
    await checkCheckoutRateLimit(req());
    expect(insertMock).not.toHaveBeenCalled();
  });
});

describe("getClientIpHash — never crashes or produces a predictable/empty hash on a hostile header", () => {
  it("hashes a completely absent IP to a stable non-empty value rather than throwing", () => {
    const hash = getClientIpHash(req());
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("uses the LAST hop of x-forwarded-for (the nearest trusted proxy's observation), not the attacker-controlled first entry", () => {
    const attackerClaimed = getClientIpHash(req({ "x-forwarded-for": "1.2.3.4" }));
    const withProxyChain = getClientIpHash(req({ "x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.9.9.9" }));
    const lastHopOnly = getClientIpHash(req({ "x-forwarded-for": "9.9.9.9" }));
    expect(withProxyChain).toBe(lastHopOnly);
    expect(withProxyChain).not.toBe(attackerClaimed);
  });

  it("a header stuffed with garbage/injection-shaped content still resolves to a deterministic hash, no throw", () => {
    expect(() =>
      getClientIpHash(req({ "x-forwarded-for": "'; DROP TABLE users; --, <script>alert(1)</script>" }))
    ).not.toThrow();
  });
});
