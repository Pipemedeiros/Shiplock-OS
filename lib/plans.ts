/**
 * Dormant Stripe checkout identities.
 *
 * Pricing is intentionally not represented here. Billing is parked and every
 * prior amount/term is superseded. These stable ids remain only so historical
 * webhook metadata and the disabled checkout path can be interpreted without
 * inventing a new offer. Re-enabling billing requires an approved, measured
 * cost model and a separately reviewed plan migration.
 */

export type PlanId = "monthly" | "six_month" | "annual";
export type PlanMode = "subscription" | "payment";

export interface Plan {
  id: PlanId;
  name: string;
  mode: PlanMode;
  priceEnvVar: string;
  months: number;
}

export const PLANS: Plan[] = [
  {
    id: "monthly",
    name: "Legacy monthly",
    mode: "subscription",
    priceEnvVar: "STRIPE_PRICE_ID",
    months: 1,
  },
  {
    id: "six_month",
    name: "Legacy six-month",
    mode: "payment",
    priceEnvVar: "STRIPE_PRICE_ID_SIX_MONTH",
    months: 6,
  },
  {
    id: "annual",
    name: "Legacy twelve-month",
    mode: "payment",
    priceEnvVar: "STRIPE_PRICE_ID_ANNUAL",
    months: 12,
  },
];

export function getPlan(id: string): Plan | undefined {
  return PLANS.find((plan) => plan.id === id);
}
