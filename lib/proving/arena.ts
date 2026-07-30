import { attemptProvingBranch, deleteProvingBranch, runOnBranch } from "./branch";
import { assertProvingTarget, type CustomerAutonomySettings } from "./guard";
import { assessReplicability, buildReplicaPlan } from "./replica";
import type { PgPolicy } from "./policyTypes";

// An arena is somewhere it is safe to attack.
//
// There are two, they have very different economics, and every layer above this
// one should not care which it got:
//
//   branch   A Supabase preview branch of the customer's own project. Highest
//            fidelity — real schema, real policies, real extensions — and
//            Pro-only, because Supabase gates Branching behind it.
//   replica  The table and its policies rebuilt in a throwaway schema on
//            ShipLock's own project. Works on every plan, costs the customer
//            nothing, and is lower fidelity: it can only reconstruct policies
//            that depend on the row and the caller.
//
// The customer pays for ShipLock and nothing else (CLAUDE.md), so `replica` is
// the path that must always work and `branch` is the upgrade. Expressing both as
// one interface is what keeps that from turning into two copies of the probe
// logic that drift apart.
//
// Adding a third arena later — a full sandboxed deployment of their app, which
// is what Strix-class testing would need — means implementing this interface,
// not rewriting the callers.

export interface Arena {
  kind: "branch" | "replica";
  /** Schema that every statement must target. The agent guard is scoped to it. */
  schema: string;
  /** Human-readable, for the evidence trail. */
  description: string;
  run(sql: string): Promise<Record<string, unknown>[]>;
  teardown(): Promise<void>;
}

export interface ArenaRequest {
  /** The customer's project, for the branch path. */
  customerToken: string;
  customerRef: string;
  settings: CustomerAutonomySettings;
  /** One table to rebuild, for the replica path. */
  table: string;
  ownerColumn: string;
  policies: PgPolicy[];
}

/** ShipLock's own proving project, used by the replica path. */
export interface ProvingHost {
  token: string;
  projectRef: string;
  run(projectRef: string, sql: string): Promise<Record<string, unknown>[]>;
}

/**
 * Opens the best arena available, or explains why it could not.
 *
 * Branch first when the plan allows it, because higher fidelity means fewer
 * findings we have to caveat. Replica otherwise. A `null` arena is never an
 * error state — a customer on the free plan with a policy too complex to
 * reconstruct simply gets the static reasoner's inference, honestly labelled.
 */
export async function openArena(
  request: ArenaRequest,
  host: ProvingHost | null
): Promise<{ arena: Arena | null; reason: string }> {
  const attempt = await attemptProvingBranch(request.customerToken, request.customerRef);

  if (attempt.handle) {
    const handle = attempt.handle;
    return {
      arena: {
        kind: "branch",
        // A branch carries the customer's own schema, so probes target public.
        schema: "public",
        description: "a temporary copy of your project's schema, with none of your data",
        run: (sql) => runOnBranch(request.customerToken, handle, request.settings, sql),
        teardown: async () => {
          await deleteProvingBranch(request.customerToken, handle.ref);
        },
      },
      reason: "",
    };
  }

  // Branching unavailable — usually the plan. Fall back to reconstruction.
  if (!host) {
    return { arena: null, reason: "No proving host configured." };
  }

  const replicable = assessReplicability(request.policies);
  if (!replicable.replicable) {
    return { arena: null, reason: replicable.reason };
  }

  const plan = buildReplicaPlan(
    `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`,
    request.table,
    request.ownerColumn,
    request.policies
  );

  try {
    await host.run(host.projectRef, plan.setupSql);
  } catch (err) {
    return {
      arena: null,
      reason: `Could not rebuild ${request.table} for testing: ${err instanceof Error ? err.message : "setup failed"}`,
    };
  }

  return {
    arena: {
      kind: "replica",
      schema: plan.schema,
      description: "a rebuilt copy of this table and its policies on our own infrastructure, with none of your data",
      run: async (sql) => {
        // The customer-facing guard still applies: the settings that gate the
        // proving ground gate this path too, even though no customer
        // infrastructure is touched.
        assertProvingTarget(
          {
            ref: host.projectRef,
            parentRef: request.customerRef,
            isEphemeralBranch: true,
            containsProductionData: false,
          },
          request.settings
        );
        return host.run(host.projectRef, sql);
      },
      teardown: async () => {
        await host.run(host.projectRef, plan.teardownSql).catch(() => {});
      },
    },
    reason: "",
  };
}
