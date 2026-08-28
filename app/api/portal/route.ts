import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";
import { getSupabaseAdmin } from "@/lib/supabase";

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

  let session;
  try {
    session = await getStripe().billingPortal.sessions.create({
      customer: profile.stripe_customer_id,
      return_url: `${appUrl}/dashboard`,
    });
  } catch (err) {
    console.error(
      "[portal] stripe.billingPortal.sessions.create failed:",
      err instanceof Error ? err.message : err
    );
    return NextResponse.json({ error: "Couldn't open the billing portal. Try again." }, { status: 500 });
  }

  return NextResponse.json({ url: session.url });
}
