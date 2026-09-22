import { runManagementQuery } from "@/lib/deep/supabaseMgmt";
import type { ProvingHost } from "./arena";

// ShipLock's own proving project — an optional disposable replica host.
//
// Supabase Branching may be unavailable to a customer, so a preview user needs somewhere safe to
// prove a finding. That somewhere is ours: a dedicated project holding no
// customer data, where a single table and its policies are rebuilt, tested and
// dropped.
//
// Returns null when unconfigured, which disables this proof path cleanly rather
// than failing at the point of use.
export function provingHost(): ProvingHost | null {
  const token = process.env.SHIPLOCK_PROVING_TOKEN;
  const projectRef = process.env.SHIPLOCK_PROVING_PROJECT_REF;
  if (!token || !projectRef) return null;

  return {
    token,
    projectRef,
    run: (ref, sql) => runManagementQuery(token, ref, sql),
  };
}
