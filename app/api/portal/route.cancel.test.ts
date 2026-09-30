import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Q30: "Cancel subscription" opens Stripe's cancel flow for the caller's own
// active subscription and returns to /cancelled; nothing client-supplied picks
// the customer or the subscription.
const getUser = vi.fn();
const profile = vi.fn();
const createPortal = vi.fn();
const listSubscriptions = vi.fn();
vi.mock("@/lib/stripe", () => ({
  getStripe: () => ({ billingPortal: { sessions: { create: createPortal } }, subscriptions: { list: listSubscriptions } }),
}));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ auth: { getUser }, from: () => ({ select: () => ({ eq: () => ({ maybeSingle: profile }) }) }) }),
}));
const { POST } = await import("./route");
const req = (body: unknown) => new NextRequest("https://shiplock.dev/api/portal", {
  method: "POST", headers: { "content-type": "application/json", authorization: "Bearer t" }, body: JSON.stringify(body),
});

describe("POST /api/portal intent cancel", () => {
  beforeEach(() => {
    vi.stubEnv("NEXT_PUBLIC_APP_URL", "https://shiplock.dev");
    getUser.mockResolvedValue({ data: { user: { id: "u1" } } });
    profile.mockResolvedValue({ data: { stripe_customer_id: "cus_1" } });
    createPortal.mockReset().mockResolvedValue({ url: "https://billing.stripe.com/cancel" });
    listSubscriptions.mockReset().mockResolvedValue({ data: [{ id: "sub_1" }] });
  });

  it("opens the cancel flow for the caller's own active subscription and returns to /cancelled", async () => {
    const res = await POST(req({ intent: "cancel", subscription: "sub_victim" }));
    expect(await res.json()).toEqual({ url: "https://billing.stripe.com/cancel" });
    expect(listSubscriptions).toHaveBeenCalledWith({ customer: "cus_1", status: "active", limit: 1 });
    expect(createPortal).toHaveBeenCalledWith({
      customer: "cus_1",
      return_url: "https://shiplock.dev/dashboard/settings",
      flow_data: { type: "subscription_cancel", subscription_cancel: { subscription: "sub_1" },
        after_completion: { type: "redirect", redirect: { return_url: "https://shiplock.dev/cancelled" } } },
    });
  });

  it("says there is nothing to cancel when no subscription is active", async () => {
    listSubscriptions.mockResolvedValue({ data: [] });
    const res = await POST(req({ intent: "cancel" }));
    expect(res.status).toBe(404);
    expect(createPortal).not.toHaveBeenCalled();
  });
});
