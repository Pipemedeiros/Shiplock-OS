import Stripe from "stripe";

/**
 * The Stripe client, constructed on first use.
 *
 * This used to be a module-scope `new Stripe(key)` with a throw above it, which
 * meant a missing STRIPE_SECRET_KEY failed the BUILD rather than the request —
 * Next.js evaluates every route module while collecting page data, so one
 * absent billing key took the whole application down at compile time. CI never
 * passed once for exactly this reason.
 *
 * That is the wrong shape for a key that only three routes need, and it is
 * doubly wrong now that billing is parked (lib/access.ts): a capability nobody
 * is using must not be able to break a deploy.
 *
 * Server-side only — never import this in a client component.
 */
let client: Stripe | null = null;

export function getStripe(): Stripe {
  if (client) return client;

  const key = process.env.STRIPE_SECRET_KEY;
  // Thrown at CALL time, so the failure lands on the request that needed
  // billing rather than on everything else.
  if (!key) throw new Error("STRIPE_SECRET_KEY is not set: add it to .env.local.");

  client = new Stripe(key, { apiVersion: "2026-05-27.dahlia" });
  return client;
}
