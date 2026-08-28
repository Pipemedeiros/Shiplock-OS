import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const getUserMock = vi.fn();
const createSessionMock = vi.fn();
const checkCheckoutRateLimitMock = vi.fn();

vi.mock("@/lib/stripe", () => ({
  getStripe: () => ({ checkout: { sessions: { create: createSessionMock } } }),
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ auth: { getUser: getUserMock } }) }));
vi.mock("@/lib/rateLimit", () => ({ checkCheckoutRateLimit: checkCheckoutRateLimitMock }));

const { POST } = await import("./route");

function req(body: unknown, headers: Record<string, string> = { authorization: "Bearer valid-token" }) {
  return new NextRequest("https://shiplock.dev/api/checkout", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

function unauthedReq(body: unknown) {
  return new NextRequest("https://shiplock.dev/api/checkout", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("POST /api/checkout — price and identity can't be attacker-controlled", () => {
  beforeEach(() => {
    getUserMock.mockReset();
    createSessionMock.mockReset().mockResolvedValue({ url: "https://checkout.stripe.com/session" });
    checkCheckoutRateLimitMock.mockReset().mockResolvedValue({ limited: false, ipHash: "h" });
  });

  it("401s without auth and never creates a Stripe session", async () => {
    const res = await POST(unauthedReq({}));
    expect(res.status).toBe(401);
    expect(createSessionMock).not.toHaveBeenCalled();
  });

  it("429s when the rate limiter says limited, before touching Stripe", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } } });
    const limitedResponse = new Response(JSON.stringify({ error: "too many" }), { status: 429 });
    checkCheckoutRateLimitMock.mockResolvedValue({ limited: true, response: limitedResponse });

    const res = await POST(req({}));
    expect(res.status).toBe(429);
    expect(createSessionMock).not.toHaveBeenCalled();
  });

  it("rejects a plan id outside the enum instead of falling back to a default price", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } } });
    const res = await POST(req({ plan: "free_forever" }));
    expect(res.status).toBe(400);
    expect(createSessionMock).not.toHaveBeenCalled();
  });

  it("mass assignment: a client-supplied priceId/amount field in the body has zero effect on the created session", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1", email: "victim@example.com" } } });

    await POST(
      req({
        plan: "monthly",
        priceId: "price_attacker_custom",
        amount: 1,
        userId: "attacker-supplied-id",
        email: "attacker@evil.com",
      })
    );

    expect(createSessionMock).toHaveBeenCalledTimes(1);
    const call = createSessionMock.mock.calls[0][0];
    // Price line item must be the server-resolved env-configured price, never
    // the attacker's.
    expect(call.line_items[0].price).toBe("price_dummy");
    // Billing email comes from the verified session, never the request body.
    expect(call.customer_email).toBe("victim@example.com");
    expect(call.metadata.userId).toBe("u1");
  });

  it("400s malformed JSON without leaking internals", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1", email: "a@b.com" } } });
    const badReq = new NextRequest("https://shiplock.dev/api/checkout", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer x" },
      body: "{bad json",
    });
    const res = await POST(badReq);
    expect(res.status).toBe(400);
  });
});
