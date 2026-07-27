// Single source of truth for what ShipLock sells. The landing page renders
// from this list and /api/checkout resolves a plan id to a Stripe price from
// it, so the two can never drift.
//
// Structure, decided 2026-07-27: one product, three terms. Monthly is a real
// subscription with the 7-day trial. The 6- and 12-month terms are PREPAID
// one-time charges — no auto-renewal, and therefore no early-termination fee
// to enforce or disclose. That is deliberate: an auto-renewing consumer
// subscription carrying a cancellation fee is the exact structure FTC
// negative-option rules and EU consumer law treat as high-risk, and Stripe
// won't enforce one natively anyway. Prepaid sidesteps all of it and still
// pulls the cash forward.
//
// Nothing is feature-gated by term. A longer term is cheaper, that's all.

export type PlanId = "monthly" | "six_month" | "annual";

export type PlanMode = "subscription" | "payment";

export interface Plan {
  id: PlanId;
  name: string;
  /** Display price, already formatted. */
  price: string;
  /** Suffix shown next to the price. */
  per: string;
  tagline: string;
  features: string[];
  cta: string;
  featured: boolean;
  /** Stripe checkout mode. Prepaid terms are one-time charges, not subs. */
  mode: PlanMode;
  /** Env var holding this plan's Stripe price id. */
  priceEnvVar: string;
  /** Months of access granted. Monthly renews; prepaid terms expire. */
  months: number;
}

const CORE_FEATURES = [
  "Sixteen checks across four attack surfaces, continuously",
  "Every pull request re-audited; deep scans every 48 hours, critical checks hourly",
  "Fixes delivered as reviewable pull requests you merge — never applied to your database by us",
  "A live edge that blocks credential stuffing, scanners, and floods — fails open, never a real user",
  "Alerts only when something new appears — silence means you're clean",
  "Shareable Verified report for your own customers and investors",
];

export const PLANS: Plan[] = [
  {
    id: "monthly",
    name: "Monthly",
    price: "$49",
    per: "/month",
    tagline: "The engagement, billed as you go.",
    features: [...CORE_FEATURES, "First 7 days free — cancel before you're charged"],
    cta: "Start 7 days free",
    featured: true,
    mode: "subscription",
    priceEnvVar: "STRIPE_PRICE_ID",
    months: 1,
  },
  {
    id: "six_month",
    name: "Six months",
    price: "$265",
    per: "once",
    tagline: "Save 10%. Paid once, nothing recurring.",
    features: [
      ...CORE_FEATURES,
      "$44.17/month equivalent — one charge, no auto-renewal",
      "No cancellation fee, because there's nothing to cancel",
    ],
    cta: "Prepay six months",
    featured: false,
    mode: "payment",
    priceEnvVar: "STRIPE_PRICE_ID_SIX_MONTH",
    months: 6,
  },
  {
    id: "annual",
    name: "Twelve months",
    price: "$470",
    per: "once",
    tagline: "Save 20%. The cheapest way to stay covered.",
    features: [
      ...CORE_FEATURES,
      "$39.17/month equivalent — one charge, no auto-renewal",
      "No cancellation fee, because there's nothing to cancel",
    ],
    cta: "Prepay twelve months",
    featured: false,
    mode: "payment",
    priceEnvVar: "STRIPE_PRICE_ID_ANNUAL",
    months: 12,
  },
];

export function getPlan(id: string): Plan | undefined {
  return PLANS.find((p) => p.id === id);
}

/**
 * A plan is only offerable if its Stripe price id is actually configured.
 * Lets the prepaid terms ship dark until the owner creates those prices in
 * Stripe, rather than showing a button that 500s.
 */
export function isPlanConfigured(plan: Plan): boolean {
  return Boolean(process.env[plan.priceEnvVar]);
}
