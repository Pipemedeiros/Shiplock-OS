import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { getStripe } from "@/lib/stripe";
import { getSupabaseAdmin } from "@/lib/supabase";
import { checkCheckoutRateLimit } from "@/lib/rateLimit";
import { getPlan } from "@/lib/plans";

const schema = z.object({
  summary: z.string().max(300).optional(),
  // Omitted by older clients and by every existing call site — defaults to the
  // monthly subscription, which is the only plan that has ever existed.
  plan: z.enum(["monthly", "six_month", "annual"]).optional(),
});

export async function POST(req: NextRequest) {
  // Checkout requires an authenticated user — the email used for billing
  // comes from the verified session, never from the request body.
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const { data } = await admin.auth.getUser(token);
  if (!data.user?.email) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }
  const { id: userId, email } = data.user;

  const limit = await checkCheckoutRateLimit(req);
  if (limit.limited) return limit.response;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body." }, { status: 400 });
  }

  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }
  const { summary } = parsed.data;

  const plan = getPlan(parsed.data.plan ?? "monthly");
  if (!plan) {
    return NextResponse.json({ error: "Unknown plan." }, { status: 400 });
  }

  // Each plan carries its own Stripe price id env var. A prepaid term that the
  // owner hasn't created in Stripe yet resolves to nothing here, so it fails
  // with a clear 400 rather than a Stripe "No such price" 500.
  const priceId = process.env[plan.priceEnvVar];
  if (!priceId) {
    return NextResponse.json({ error: "That plan isn't available yet." }, { status: 400 });
  }

  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (!appUrl) {
    return NextResponse.json({ error: "Checkout is not configured." }, { status: 500 });
  }

  let session;
  try {
    session = await getStripe().checkout.sessions.create({
      // Prepaid terms are one-time charges, not subscriptions — nothing
      // auto-renews, so there is no cancellation to fee. See lib/plans.ts.
      mode: plan.mode,
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      // The 7-day trial belongs to the monthly subscription only; Stripe
      // rejects subscription_data on a one-time payment session.
      ...(plan.mode === "subscription"
        ? { subscription_data: { trial_period_days: 7 } }
        : {}),
      metadata: {
        userId,
        summary: summary ?? "",
        planId: plan.id,
        // Read by /api/webhook to set paid_until on prepaid terms.
        months: String(plan.months),
      },
      success_url: `${appUrl}/?payment=success`,
      cancel_url: `${appUrl}/?payment=cancelled`,
    });
  } catch (err) {
    console.error(
      "[checkout] stripe.checkout.sessions.create failed:",
      err instanceof Error ? err.message : err
    );
    return NextResponse.json({ error: "Checkout failed. Try again." }, { status: 500 });
  }

  return NextResponse.json({ url: session.url });
}
