/**
 * The single gate for product access.
 *
 * The MVP is open: anyone with an account gets the full product, because the
 * thing we need right now is people using it, not revenue from the ten of them.
 * Stripe, the billing portal and the monitoring emails are PARKED — the code is
 * intact and untouched, and flipping BILLING_ENABLED back to true restores the
 * paywall everywhere at once.
 *
 * Why a flag rather than deleting the checks: the paywall has regressed twice in
 * this codebase's history (v1 blurred a full response in CSS; column grants on
 * scan_history silently reverted after a clean migration). Both times the cause
 * was paywall logic living in more than one place. Keeping every read site
 * calling hasProductAccess() means the paywall is still exactly one decision —
 * it is just currently answering "yes".
 *
 * The invariant that does NOT change: is_paid is still the only source of truth
 * for whether someone paid. Nothing here writes it, and no read site may
 * reintroduce a second one.
 */

/** Flip to true to switch billing back on. Nothing else needs to change. */
export const BILLING_ENABLED = false;

/** Email alerts are parked with billing — see MVP scope in MVP-SPEC.md §4. */
export const EMAIL_ALERTS_ENABLED = false;

export interface AccessProfile {
  is_paid?: boolean | null;
}

/**
 * True when this account may use the product.
 *
 * While billing is parked, any signed-in account qualifies — but a null profile
 * never does. "Signed in" is still a requirement; the audit reads a customer's
 * private source code, and that is not something an anonymous caller gets.
 */
export function hasProductAccess(profile: AccessProfile | null | undefined): boolean {
  if (!profile) return false;
  if (!BILLING_ENABLED) return true;
  return profile.is_paid === true;
}

/**
 * Applied to the scheduled passes, which used to filter on `.eq("is_paid", true)`.
 * With billing parked, every enrolled account is in scope.
 */
export function paidFilterColumn(): { column: "is_paid"; value: boolean } | null {
  return BILLING_ENABLED ? { column: "is_paid", value: true } : null;
}

/**
 * Applies the paid filter to a Supabase query only when billing is on.
 *
 * The scheduled passes used to hard-code `.eq("is_paid", true)`, which with
 * billing parked would have made every cron pass iterate over zero users —
 * exactly the "enrolled nobody" bug this repo has already shipped once.
 */
export function withPaidFilter<T>(query: T): T {
  if (!BILLING_ENABLED) return query;
  // The constraint is expressed as a cast rather than a type parameter bound:
  // Supabase's builder type is recursive enough that binding it here makes the
  // checker give up with "type instantiation is excessively deep". The runtime
  // contract is narrow and stable — .eq() on a filter builder returns the same
  // builder — so a cast is the honest cost of keeping tsc fast.
  return (query as unknown as { eq(column: string, value: unknown): T }).eq("is_paid", true);
}
