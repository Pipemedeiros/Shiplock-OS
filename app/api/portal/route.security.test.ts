import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const getUserMock = vi.fn();
const profileSingleMock = vi.fn();
const profileEqMock = vi.fn();
const createPortalMock = vi.fn();

vi.mock("@/lib/stripe", () => ({ stripe: { billingPortal: { sessions: { create: createPortalMock } } } }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: getUserMock },
    from: () => ({
      select: () => ({
        eq: (col: string, val: string) => {
          profileEqMock(col, val);
          return { maybeSingle: profileSingleMock };
        },
      }),
    }),
  }),
}));

const { POST } = await import("./route");

function req(headers: Record<string, string> = {}, body: unknown = {}) {
  return new NextRequest("https://shiplock.dev/api/portal", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("POST /api/portal — IDOR: billing customer always resolved from the caller's own row", () => {
  beforeEach(() => {
    getUserMock.mockReset();
    profileSingleMock.mockReset();
    profileEqMock.mockReset();
    createPortalMock.mockReset().mockResolvedValue({ url: "https://billing.stripe.com/session" });
  });

  it("401s without auth", async () => {
    const res = await POST(req());
    expect(res.status).toBe(401);
    expect(createPortalMock).not.toHaveBeenCalled();
  });

  it("402s when the caller has never subscribed", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    profileSingleMock.mockResolvedValue({ data: null });
    const res = await POST(req({ authorization: "Bearer t" }));
    expect(res.status).toBe(402);
    expect(createPortalMock).not.toHaveBeenCalled();
  });

  it("IDOR: a body-supplied stripe_customer_id/customerId is completely ignored — only the caller's own row is read", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "victim-id" } } });
    profileSingleMock.mockResolvedValue({ data: { stripe_customer_id: "cus_victim_real" } });

    await POST(
      req({ authorization: "Bearer t" }, { stripe_customer_id: "cus_attacker_target", customerId: "cus_attacker_target" })
    );

    expect(profileEqMock).toHaveBeenCalledWith("id", "victim-id");
    expect(createPortalMock).toHaveBeenCalledWith(
      expect.objectContaining({ customer: "cus_victim_real" })
    );
  });
});
