import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { stripe } from "@/lib/stripe";

const schema = z.object({
  email: z.string().email(),
  grade: z.string().max(1).optional(),
  summary: z.string().max(300).optional(),
});

export async function POST(req: NextRequest) {
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
  const { email, grade, summary } = parsed.data;

  const priceId = process.env.STRIPE_PRICE_ID;
  if (!priceId) {
    return NextResponse.json({ error: "Checkout is not configured." }, { status: 500 });
  }

  const appUrl = process.env.NEXT_PUBLIC_APP_URL;
  if (!appUrl) {
    return NextResponse.json({ error: "Checkout is not configured." }, { status: 500 });
  }

  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    payment_method_types: ["card"],
    customer_email: email,
    line_items: [{ price: priceId, quantity: 1 }],
    metadata: {
      grade: grade ?? "",
      summary: summary ?? "",
    },
    success_url: `${appUrl}/?payment=success`,
    cancel_url: `${appUrl}/?payment=cancelled`,
  });

  return NextResponse.json({ url: session.url });
}
