import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

const constructEventMock = vi.fn();
const insertEventMock = vi.fn();
const profileUpdateEqMock = vi.fn();
const emailSendMock = vi.fn();

vi.mock("@/lib/stripe", () => ({ stripe: { webhooks: { constructEvent: constructEventMock } } }));
vi.mock("resend", () => ({ Resend: class { emails = { send: emailSendMock }; } }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "stripe_webhook_events") {
        return { insert: insertEventMock };
      }
      if (table === "user_profiles") {
        return {
          update: (patch: unknown) => ({
            eq: (col: string, val: string) => {
              profileUpdateEqMock(col, val, patch);
              return { select: () => Promise.resolve({ data: [{ id: "u1" }], error: null }) };
            },
          }),
        };
      }
      // subscribers insert — fire and forget
      return { insert: () => Promise.resolve({ error: null }) };
    },
  }),
}));

const { POST } = await import("./route");

function req(rawBody: string, sig: string | null) {
  return new NextRequest("https://shiplock.dev/api/webhook", {
    method: "POST",
    headers: sig ? { "stripe-signature": sig } : {},
    body: rawBody,
  });
}

describe("POST /api/webhook — forged/replayed Stripe events must not grant access", () => {
  beforeEach(() => {
    constructEventMock.mockReset();
    insertEventMock.mockReset().mockResolvedValue({ error: null });
    profileUpdateEqMock.mockReset();
    emailSendMock.mockReset();
  });

  it("400s with no stripe-signature header at all, without touching Stripe's SDK", async () => {
    const res = await POST(req(JSON.stringify({ type: "checkout.session.completed" }), null));
    expect(res.status).toBe(400);
    expect(constructEventMock).not.toHaveBeenCalled();
  });

  it("400s a forged/tampered payload — a signature that doesn't verify grants nothing", async () => {
    constructEventMock.mockImplementation(() => {
      throw new Error("No signatures found matching the expected signature for payload");
    });
    // Attacker crafts a body claiming is_paid should go true, signs it with
    // nothing real.
    const res = await POST(
      req(JSON.stringify({ type: "checkout.session.completed", data: { object: {} } }), "forged-sig")
    );
    const body = await res.json();
    expect(res.status).toBe(400);
    // Generic error only — never echoes Stripe's internal exception detail.
    expect(body.error).toBe("Invalid signature");
    expect(insertEventMock).not.toHaveBeenCalled();
    expect(profileUpdateEqMock).not.toHaveBeenCalled();
  });

  it("replay protection: a duplicate event.id is not reprocessed a second time", async () => {
    constructEventMock.mockReturnValue({
      id: "evt_123",
      type: "checkout.session.completed",
      data: { object: { customer_details: { email: "user@example.com" }, customer: "cus_1", mode: "subscription" } },
    });
    // Simulates Postgres's unique-constraint violation on a re-delivered event.
    insertEventMock.mockResolvedValue({ error: { code: "23505", message: "duplicate key" } });

    const res = await POST(req("{}", "valid-sig"));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true, duplicate: true });
    // The side effect (granting is_paid) must not run a second time.
    expect(profileUpdateEqMock).not.toHaveBeenCalled();
  });

  it("fails closed (does not grant access) on an unexpected idempotency-table error", async () => {
    constructEventMock.mockReturnValue({
      id: "evt_456",
      type: "checkout.session.completed",
      data: { object: { customer_details: { email: "user@example.com" }, customer: "cus_1" } },
    });
    insertEventMock.mockResolvedValue({ error: { code: "50000", message: "db is on fire" } });

    const res = await POST(req("{}", "valid-sig"));
    expect(res.status).toBe(500);
    expect(profileUpdateEqMock).not.toHaveBeenCalled();
  });

  it("customer.subscription.deleted revokes access scoped to the correct customer only", async () => {
    constructEventMock.mockReturnValue({
      id: "evt_789",
      type: "customer.subscription.deleted",
      data: { object: { customer: "cus_victim" } },
    });
    insertEventMock.mockResolvedValue({ error: null });

    await POST(req("{}", "valid-sig"));

    expect(profileUpdateEqMock).toHaveBeenCalledWith(
      "stripe_customer_id",
      "cus_victim",
      expect.objectContaining({ is_paid: false })
    );
  });
});
