import { describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const getUserMock = vi.fn();
const createSessionMock = vi.fn();

vi.mock("@/lib/access", () => ({ BILLING_ENABLED: false }));
vi.mock("@/lib/stripe", () => ({
  getStripe: () => ({ checkout: { sessions: { create: createSessionMock } } }),
}));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ auth: { getUser: getUserMock } }),
}));
vi.mock("@/lib/rateLimit", () => ({
  checkCheckoutRateLimit: vi.fn(),
}));

const { POST } = await import("./route");

describe("POST /api/checkout while pricing is undecided", () => {
  it("refuses before authentication, rate limits, or Stripe can run", async () => {
    const request = new NextRequest("https://shiplock.dev/api/checkout", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ plan: "monthly" }),
    });

    const response = await POST(request);

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "Billing is not available during the preview.",
    });
    expect(getUserMock).not.toHaveBeenCalled();
    expect(createSessionMock).not.toHaveBeenCalled();
  });
});
