import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { stripe } from "@/lib/stripe";
import { getSupabaseAdmin } from "@/lib/supabase";
import { checkCheckoutRateLimit } from "@/lib/rateLimit";

const schema = z.object({
  summary: z.string().max(300).optional(),
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

  const priceId = process.env.STRIPE_PRICE_ID;
  if (!priceId) {
    return NextResponse.json({ error: "Checkout is not configured." }, { status: 500 });
  }

  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (!appUrl) {
    return NextResponse.json({ error: "Checkout is not configured." }, { status: 500 });
  }

  let session;
  try {
    session = await stripe.checkout.sessions.create({
      mode: "subscription",
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{ price: priceId, quantity: 1 }],
      subscription_data: {
        trial_period_days: 7,
      },
      metadata: {
        userId,
        summary: summary ?? "",
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
