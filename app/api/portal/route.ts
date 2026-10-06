import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";
import { getSupabaseAdmin } from "@/lib/supabase";
import { bearerMfaOk } from "@/lib/mfa";

// Stripe billing portal — self-serve cancel/card-update. Auth mirrors
// /api/checkout: bearer token verified server-side, and the Stripe customer
// is resolved from user_profiles.stripe_customer_id (written by the webhook
// on checkout.session.completed), never from anything client-supplied.
export async function POST(req: NextRequest) {
  const token = req.headers.get("authorization")?.replace("Bearer ", "");
  if (!token) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const admin = getSupabaseAdmin();
  const { data } = await admin.auth.getUser(token);
  if (!data.user) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }
  if (!bearerMfaOk(data.user, token)) return NextResponse.json({ error: "Enter the code from your authenticator app first." }, { status: 403 });

  const { data: profile } = await admin
    .from("user_profiles")
    .select("stripe_customer_id")
    .eq("id", data.user.id)
    .maybeSingle();

  if (!profile?.stripe_customer_id) {
    // Never subscribed (or webhook hasn't landed yet) — nothing to manage.
    return NextResponse.json(
      { error: "No subscription found for this account." },
      { status: 402 }
    );
  }

  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (!appUrl) {
    return NextResponse.json({ error: "Billing portal is not configured." }, { status: 500 });
  }

  // Q30: "cancel" opens Stripe's cancel flow for the caller's own active
  // subscription (looked up from their customer, never from the body) and
  // lands on /cancelled; anything else opens the portal as before.
  const body = (await req.json().catch(() => ({}))) as { intent?: unknown };
  const stripe = getStripe();
  let session;
  try {
    if (body.intent === "cancel") {
      const active = await stripe.subscriptions.list({ customer: profile.stripe_customer_id, status: "active", limit: 1 });
      const subscription = active.data[0]?.id;
      if (!subscription) return NextResponse.json({ error: "There is no active subscription to cancel." }, { status: 404 });
      session = await stripe.billingPortal.sessions.create({
        customer: profile.stripe_customer_id,
        return_url: `${appUrl}/dashboard/settings`,
        flow_data: { type: "subscription_cancel", subscription_cancel: { subscription },
          after_completion: { type: "redirect", redirect: { return_url: `${appUrl}/cancelled` } } },
      });
    } else {
      session = await stripe.billingPortal.sessions.create({
        customer: profile.stripe_customer_id,
        return_url: `${appUrl}/dashboard`,
      });
    }
  } catch (err) {
    console.error(
      "[portal] stripe.billingPortal.sessions.create failed:",
      err instanceof Error ? err.message : err
    );
    return NextResponse.json({ error: "Couldn't open the billing portal. Try again." }, { status: 500 });
  }

  return NextResponse.json({ url: session.url });
}
