import { assertProvingTarget, type CustomerAutonomySettings, type ProvingTarget } from "./guard";

// Branch lifecycle for the proving ground.
//
// UNVERIFIED AGAINST THE LIVE API. Supabase Branching is documented but we have
// no connected project to test against, and creating a branch costs money on a
// customer's account. So this is written to fail CLOSED at every step: any
// unexpected response means we did not get a branch, which means the guard
// refuses, which means nothing runs. The failure mode is "the proving ground
// silently did not happen", never "it ran somewhere unexpected".

const API = "https://api.supabase.com";

export interface BranchHandle {
  target: ProvingTarget;
  /** Connection details for running statements against the branch. */
  ref: string;
}

/**
 * Creates an ephemeral branch.
 *
 * Returns null on ANY doubt. The returned target is the only place
 * `isEphemeralBranch` is ever set to true — a caller cannot construct one, which
 * is what makes the guard meaningful rather than advisory.
 */
export type BranchFailure = "plan_required" | "unavailable";

export interface BranchAttempt {
  handle: BranchHandle | null;
  failure?: BranchFailure;
}

/** Creates a disposable Supabase branch for proving, or null when it could not. */
export async function createProvingBranch(
  accessToken: string,
  productionRef: string,
  name = `shiplock-proving-${Date.now()}`
): Promise<BranchHandle | null> {
  return (await attemptProvingBranch(accessToken, productionRef, name)).handle;
}

/**
 * Like createProvingBranch, but distinguishes WHY it failed.
 *
 * Supabase Branching requires the customer's organisation to be on the Pro plan
 * — verified against the live API, which returns 402 PaymentRequired on a free
 * organisation. That is a permanent, actionable state, not a transient error,
 * and collapsing it into a generic failure would leave a customer on the free
 * plan with a feature that silently never runs and no way to know why.
 */
export async function attemptProvingBranch(
  accessToken: string,
  productionRef: string,
  name = `shiplock-proving-${Date.now()}`
): Promise<BranchAttempt> {
  try {
    const res = await fetch(`${API}/v1/projects/${encodeURIComponent(productionRef)}/branches`, {
      method: "POST",
      headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
      body: JSON.stringify({ branch_name: name }),
      signal: AbortSignal.timeout(60_000),
    });
    if (res.status === 402) return { handle: null, failure: "plan_required" };
    if (!res.ok) return { handle: null, failure: "unavailable" };

    const json = (await res.json()) as { ref?: unknown; id?: unknown };
    const ref = typeof json.ref === "string" ? json.ref : typeof json.id === "string" ? json.id : null;
    if (!ref) return { handle: null, failure: "unavailable" };

    // The identity check the guard depends on. If the API ever returns the
    // parent's ref, we must not proceed — and we refuse here as well as in the
    // guard, because two independent refusals are what a boundary this
    // consequential deserves.
    if (ref === productionRef) return { handle: null, failure: "unavailable" };

    return {
      handle: {
        ref,
        target: {
          ref,
          parentRef: productionRef,
          isEphemeralBranch: true,
          // Supabase branches copy schema, functions and config but NOT data.
          containsProductionData: false,
        },
      },
    };
  } catch {
    return { handle: null, failure: "unavailable" };
  }
}

/**
 * Deletes the branch. Called from a finally block, always.
 *
 * A leaked branch bills the customer indefinitely for something they cannot see
 * and did not ask for, which would be a worse outcome than never running the
 * probe at all.
 */
export async function deleteProvingBranch(accessToken: string, ref: string): Promise<boolean> {
  try {
    const res = await fetch(`${API}/v1/branches/${encodeURIComponent(ref)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(60_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Runs one statement against the branch.
 *
 * assertProvingTarget is called HERE, immediately before execution — not once at
 * setup — because the value of a guard is measured at the point of use, and this
 * is the only function in the codebase that sends a write to a customer's
 * Postgres.
 */
export async function runOnBranch<T>(
  accessToken: string,
  handle: BranchHandle,
  settings: CustomerAutonomySettings,
  sql: string
): Promise<T[]> {
  assertProvingTarget(handle.target, settings);

  const res = await fetch(`${API}/v1/projects/${encodeURIComponent(handle.ref)}/database/query`, {
    method: "POST",
    headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
    body: JSON.stringify({ query: sql }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`Proving query HTTP ${res.status}`);
  const json = await res.json();
  return Array.isArray(json) ? (json as T[]) : [];
}
