// The guard that makes the proving ground defensible.
//
// CLAUDE.md's doctrine is explicit and this module is its enforcement: "we never
// attack the customer's production app. We attack a copy of it, on their behalf,
// and report what happened." Everything else in the proving ground — branches,
// seeding, probes — is ordinary engineering. THIS is the part that must be
// impossible to get wrong, because getting it wrong once means running an
// adversarial probe against a real database holding real users' data.
//
// It is modelled on assertReadOnly in lib/deep/supabaseMgmt.ts, and for the same
// reason: a boundary that matters is enforced at the moment of use by a function
// that throws, not by a convention that a future edit can quietly drop.
//
// THE RULES, in the order they are checked:
//   1. The target must be explicitly identified as an ephemeral branch.
//   2. Its ref must differ from the production project's ref.
//   3. It must be marked as carrying no production data.
//   4. The customer must not have the kill switch on.
// Any failure throws. There is no permissive path, no override flag, and no
// "force" parameter — if one is ever added, this comment is the argument
// against it.

export class ProvingGroundViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProvingGroundViolation";
  }
}

export interface ProvingTarget {
  /** The branch's own project ref. */
  ref: string;
  /** The production project this branch was created from. */
  parentRef: string;
  /** Set only by the branch creation path, never by a caller. */
  isEphemeralBranch: boolean;
  /**
   * Whether Supabase created this branch WITHOUT copying production data.
   * Branch creation copies schema, functions and config but not rows; this
   * records that we confirmed it rather than assumed it.
   */
  containsProductionData: boolean;
}

export interface CustomerAutonomySettings {
  /** Per-customer "monitor only, never act". Honoured everywhere. */
  killSwitchOn: boolean;
  /** Explicit opt-in. The proving ground never runs by default. */
  provingGroundEnabled: boolean;
}

/**
 * Refuses to proceed unless the target is a verified ephemeral branch.
 *
 * Called immediately before ANY statement is executed against a proving target.
 * Not at setup, not once per run — immediately before, every time, because the
 * value of a guard is measured at the point of use.
 */
export function assertProvingTarget(
  target: ProvingTarget | null | undefined,
  settings: CustomerAutonomySettings
): asserts target is ProvingTarget {
  if (!target) {
    throw new ProvingGroundViolation("No proving target supplied. Refusing to run against anything.");
  }

  if (!target.isEphemeralBranch) {
    throw new ProvingGroundViolation(
      "Target is not an ephemeral branch. The proving ground never runs against a project that was not created as a throwaway copy."
    );
  }

  if (!target.ref || typeof target.ref !== "string") {
    throw new ProvingGroundViolation("Proving target has no usable project ref.");
  }

  // The check that catches the mistake that actually happens: a bug upstream
  // hands us the production ref while still claiming branch status.
  if (target.ref === target.parentRef) {
    throw new ProvingGroundViolation(
      `Proving target ref (${target.ref}) is identical to the production project ref. This is production. Refusing.`
    );
  }

  if (target.containsProductionData) {
    throw new ProvingGroundViolation(
      "Proving target is marked as containing production data. The proving ground only ever runs against a data-less replica seeded with synthetic tenants."
    );
  }

  if (settings.killSwitchOn) {
    throw new ProvingGroundViolation(
      "This customer has the kill switch on (monitor only, never act). Refusing to run the proving ground."
    );
  }

  if (!settings.provingGroundEnabled) {
    throw new ProvingGroundViolation(
      "The proving ground is not enabled for this customer. It never runs without an explicit opt-in."
    );
  }
}

/**
 * True when it is safe to run. Never used INSTEAD of the assert — callers use
 * this to decide whether to start, and the assert to decide whether to execute.
 */
export function canProve(
  target: ProvingTarget | null | undefined,
  settings: CustomerAutonomySettings
): boolean {
  try {
    assertProvingTarget(target, settings);
    return true;
  } catch {
    return false;
  }
}
