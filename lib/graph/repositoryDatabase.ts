import { getSupabaseAdmin } from "@/lib/supabase";
import { getDirectRepositoryBindings } from "@/lib/deep/databaseRepositoryBinding";
import { getSupabaseRepositoryBindings } from "@/lib/deep/supabaseRepositoryBinding";
import { loadCurrentDatabaseEvidence, type DatabaseEvidence } from "./databaseSource";
import type { GraphInput } from "./graph";

/** These remain separate observations: customer confirmation does not establish
 * a shared physical database, environment, or deployment across transports. */
export interface RepositoryDatabaseEvidence extends DatabaseEvidence {
  repositoryId: string;
  associationMethod: "customer_confirmed";
}

/**
 * Project one customer-confirmed database observation into the cross-surface
 * reasoner. Two control-capable transports remain ambiguous: confirmation says
 * each is related to the repository, not that they observe the same physical
 * database or environment, so choosing or merging them would invent evidence.
 * Endpoint reports never become control facts because their RLS readability is
 * explicitly unknown.
 */
export function projectRepositoryDatabaseEvidence(evidence: RepositoryDatabaseEvidence): Partial<GraphInput> {
  if (evidence.admission !== "connection-matched") return {};
  const direct = evidence.snapshots.directPostgresSnapshot;
  const management = evidence.snapshots.supabaseManagementSnapshot;
  if (Number(Boolean(direct)) + Number(Boolean(management)) !== 1) return {};
  if (direct) return {
    correlationScope: "repository-bound",
    authzProvider: direct.authzProvider,
    policies: direct.policies,
    scanTables: direct.scanTables,
  };
  if (management) return {
    correlationScope: "repository-bound",
    authzProvider: management.authzProvider,
    policies: management.policies,
    ...(management.advisors !== undefined ? { advisors: management.advisors } : {}),
    authConfig: management.authConfig,
  };
  return {};
}

/** The database evidence bound to a repository, with how the binding was made
 * and whether it is admitted. */
export async function loadRepositoryDatabaseEvidence(userId: string, repositoryId: string): Promise<RepositoryDatabaseEvidence> {
  const result: RepositoryDatabaseEvidence = {
    repositoryId, associationMethod: "customer_confirmed", admission: "unknown", snapshots: {},
  };
  try {
    const { data, error } = await getSupabaseAdmin().from("graph_facts").select("facts")
      .eq("user_id", userId).eq("collector", "db").maybeSingle();
    if (error || !data) return result;
    const current = await loadCurrentDatabaseEvidence(userId, data.facts);
    const direct = current.snapshots.directPostgresSnapshot;
    const management = current.snapshots.supabaseManagementSnapshot;
    const endpoint = current.snapshots.supabaseEndpointSnapshot;
    // Each failure is isolated, but a partial transport never borrows fields.
    await Promise.all([
      direct && (async () => {
        const context = await getDirectRepositoryBindings(userId);
        if (context.available && context.connectionFingerprint === direct.connectionFingerprint &&
            context.bindings.some((binding) => binding.repositoryId === repositoryId)) {
          result.snapshots.directPostgresSnapshot = direct;
        }
      })().catch(() => {}),
      management && (async () => {
        const context = await getSupabaseRepositoryBindings(userId, "supabase-management");
        if (context.available && context.connectionFingerprint === management.connectionFingerprint &&
            context.projectRef === management.projectRef && context.endpointUrl === null &&
            context.bindings.some((binding) => binding.repositoryId === repositoryId)) {
          result.snapshots.supabaseManagementSnapshot = management;
        }
      })().catch(() => {}),
      endpoint && (async () => {
        const context = await getSupabaseRepositoryBindings(userId, "supabase-scan");
        if (context.available && context.connectionFingerprint === endpoint.connectionFingerprint &&
            context.projectRef === endpoint.projectRef && context.endpointUrl === endpoint.endpointUrl &&
            context.bindings.some((binding) => binding.repositoryId === repositoryId)) {
          result.snapshots.supabaseEndpointSnapshot = endpoint;
        }
      })().catch(() => {}),
    ]);
    if (Object.keys(result.snapshots).length) result.admission = "connection-matched";
  } catch { /* Unknown is preserved on storage or protocol failure. */ }
  return result;
}
