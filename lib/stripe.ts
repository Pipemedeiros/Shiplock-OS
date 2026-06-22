import Stripe from "stripe";

const key = process.env.STRIPE_SECRET_KEY;
if (!key) throw new Error("STRIPE_SECRET_KEY is not set — add it to .env.local.");

// Server-side only — never import in client components.
export const stripe = new Stripe(key, {
  apiVersion: "2026-05-27.dahlia",
});
