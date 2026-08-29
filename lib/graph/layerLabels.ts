// Pure display helpers for correlation layers.
//
// Deliberately in their own module with NO imports: layerStatus.ts pulls in
// getSupabaseAdmin (service-role), and these helpers are needed by client
// components like FixCard. Importing them from layerStatus.ts would drag the
// service-role client into the browser bundle — the exact thing CLAUDE.md's
// "never import supabase.ts in a client component" rule exists to prevent, and
// the kind of leak that is invisible until someone reads a bundle.

/**
 * Collector namespaces, as stored on a finding's `correlation.surfaces`, mapped
 * to the customer-facing layer names.
 *
 * The graph's internal vocabulary ("source", "db") is not the customer's. They
 * connected GitHub and Supabase; "source" would make them translate. `config`
 * folds into database because that is where a customer experiences it — an auth
 * setting is not a separate thing they own.
 */
const SURFACE_LABEL: Record<string, string> = {
  source: "code",
  db: "database",
  config: "database",
  traffic: "traffic",
  runtime: "live config",
};

/** Display order, so the strip reads the same way on every finding. */
const STRIP_ORDER: string[] = ["code", "database", "live config", "traffic", "email/DNS"];

/**
 * Build the agreement strip's layer list from a finding's stored surfaces.
 *
 * Every known layer is returned, agreed or not, because the unlit ones carry
 * real information: "confirmed by code and database, and traffic has nothing to
 * say about it" is a more honest picture than showing only what agreed.
 */
export function correlationLayers(
  surfaces: string[] | undefined
): { label: string; agreed: boolean }[] {
  const agreed = new Set((surfaces ?? []).map((s) => SURFACE_LABEL[s]).filter(Boolean));
  return STRIP_ORDER.map((label) => ({ label, agreed: agreed.has(label) }));
}
