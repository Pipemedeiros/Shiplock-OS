import { createHash } from "crypto";
import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";
import { stripe } from "@/lib/stripe";
import { sendEmail } from "@/lib/email";
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

  // Idempotency guard: gate the entire handler on Stripe's own event.id, not
  // an application-level check-then-act query. event.id is always present
  // and guaranteed unique per event (Stripe's own recommended idempotency
  // key) — unlike stripe_subscription_id, which is nullable and was the
  // previous (racy) guard. The INSERT below is atomic: under concurrent
  // duplicate delivery, Postgres's primary-key enforcement guarantees
  // exactly one insert succeeds and the other fails with 23505, with no
  // check-then-act window. See migration 018.
  const { error: dedupeError } = await admin
    .from("stripe_webhook_events")
    .insert({ event_id: event.id, event_type: event.type });

  if (dedupeError) {
    if (dedupeError.code === "23505") {
      // Already processed (or a concurrent request is processing it right now).
      return NextResponse.json({ received: true, duplicate: true });
    }
    // Fail closed on unexpected DB errors: log and skip side effects rather
    // than risk double-processing without a working idempotency guard.
    console.error("[webhook] idempotency insert error:", dedupeError.message);
    return NextResponse.json({ error: "Webhook processing failed" }, { status: 500 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const email = session.customer_details?.email ?? session.customer_email;
    const customerId = session.customer as string;
    const subscriptionId = session.subscription as string | null;

    // Prepaid terms (mode: "payment") buy a fixed window rather than a
    // renewing subscription, so access has to carry an end date. The monthly
    // subscription leaves paid_until null and is governed by Stripe's own
    // renewal/cancel events instead. Expiry is swept daily — see
    // app/api/monitor/scheduled/route.ts.
    const months = Number(session.metadata?.months ?? "0");
    const paidUntil =
      session.mode === "payment" && months > 0
        ? new Date(Date.now() + months * 30 * 24 * 60 * 60 * 1000).toISOString()
        : null;

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
        .update({ is_paid: true, stripe_customer_id: customerId, paid_until: paidUntil })
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

      if (profileUpdated) {
        await admin
          .from("subscribers")
          .insert({
            email,
            stripe_customer_id: customerId,
            stripe_subscription_id: subscriptionId,
          })
          .then(() => {}, () => {});

        // Best-effort: access is already granted above, so a failed welcome
        // email must not fail the webhook (Stripe would retry a non-2xx and
        // re-run everything). Routed through sendEmail so an API-level rejection
        // is logged rather than swallowed by a bare .catch(() => {}).
        await sendEmail(
          {
            to: email,
            subject: "ShipLock Pro — access granted",
            text: "Your ShipLock Pro subscription is active. All fixes are now unlocked, and ShipLock is monitoring your app for changes.",
          },
          "webhook"
        );
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
