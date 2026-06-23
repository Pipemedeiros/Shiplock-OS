import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";
import { Resend } from "resend";
import { stripe } from "@/lib/stripe";
import { getSupabaseAdmin } from "@/lib/supabase";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const sig = req.headers.get("stripe-signature");
  if (!sig) {
    return NextResponse.json({ error: "No signature" }, { status: 400 });
  }

  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    const ip = req.headers.get("x-forwarded-for") ?? "unknown";
    const ipHash = createHash("sha256").update(ip).digest("hex");
    console.error(`[webhook] Invalid Stripe signature — rejected request from ip_hash=${ipHash}`);
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  const admin = getSupabaseAdmin();

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const email = session.customer_details?.email ?? session.customer_email;
    const customerId = session.customer as string;
    const subscriptionId = session.subscription as string | null;

    if (email) {
      // user_profiles.id is a NOT NULL foreign key to auth.users with no
      // default, so an upsert with onConflict:'email' fails outright if no
      // row exists yet for this email (Postgres can't satisfy the FK on
      // insert). A matching row should always exist already: /api/checkout
      // requires the caller to be an authenticated Supabase user, and the
      // signup trigger creates user_profiles at that point. Use UPDATE, not
      // upsert, and log loudly — rather than silently fail — if that
      // invariant is ever violated (confirmed failing via `stripe trigger`
      // during the 2026-06-22 security audit).
      const { data: updated, error } = await admin
        .from("user_profiles")
        .update({ is_paid: true, stripe_customer_id: customerId })
        .eq("email", email)
        .select("id");

      if (error) {
        console.error("[webhook] user_profiles update error:", error.message);
      } else if (!updated || updated.length === 0) {
        console.error(
          `[webhook] No ShipLock account found for paying customer (customer=${customerId}) — payment succeeded but is_paid was not set. Manual reconciliation required.`
        );
      }
      const profileUpdated = !error && updated && updated.length > 0;

      // Idempotency guard: Stripe retries webhook deliveries, and the
      // subscribers insert + welcome email below are not naturally
      // idempotent like the upsert above. Skip both if we've already
      // recorded this subscription.
      const { data: existing } = subscriptionId
        ? await admin
            .from("subscribers")
            .select("id")
            .eq("stripe_subscription_id", subscriptionId)
            .maybeSingle()
        : { data: null };

      if (profileUpdated && !existing) {
        await admin
          .from("subscribers")
          .insert({
            email,
            stripe_customer_id: customerId,
            stripe_subscription_id: subscriptionId,
          })
          .then(() => {}, () => {});

        const resend = new Resend(process.env.RESEND_API_KEY);
        await resend.emails
          .send({
            from: process.env.RESEND_FROM_EMAIL!,
            to: email,
            subject: "ShipLock Pro — access granted",
            text: "Your ShipLock Pro subscription is active. All fixes are now unlocked. Loki is watching your app.",
          })
          .catch(() => {});
      }
    }
  }

  if (event.type === "customer.subscription.deleted") {
    const sub = event.data.object as Stripe.Subscription;
    const customerId = sub.customer as string;

    await admin
      .from("user_profiles")
      .update({ is_paid: false, monitoring_enabled: false })
      .eq("stripe_customer_id", customerId);
  }

  return NextResponse.json({ received: true });
}
