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
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  const admin = getSupabaseAdmin();

  if (event.type === "checkout.session.completed") {
    const session = event.data.object as Stripe.Checkout.Session;
    const email = session.customer_details?.email ?? session.customer_email;
    const customerId = session.customer as string;

    if (email) {
      const { error } = await admin
        .from("user_profiles")
        .upsert({ email, is_paid: true, stripe_customer_id: customerId }, { onConflict: "email" });
      if (error) console.error("[webhook] user_profiles upsert error:", error.message);

      await admin
        .from("subscribers")
        .insert({
          email,
          stripe_customer_id: customerId,
          stripe_subscription_id: session.subscription as string,
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
