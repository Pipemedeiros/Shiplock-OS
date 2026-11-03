import type { Claim, Confidence } from "./findings";

/**
 * Findings ShipLock observed outside the repository.
 *
 * Each collector stores its findings in deep_findings under its own source,
 * with no claims or confidence columns: the open-findings read used to take
 * source 'agent' only, so a replica proof, a service-role key downloaded from
 * the shipped bundle, or row security read off never reached Issues or the
 * status. This module gives every such row the evidence it actually rests on,
 * once, for the dashboard, MCP and the shareable report alike.
 *
 * Confirmed (a live, verified claim): a reproduction on a replica, or a direct
 * observation of exposure. Everything else a collector reports is a setting
 * that weakens a layer (email authentication, an edge in front, an extension),
 * read live but not a way in: To review.
 */
export const LIVE_SOURCES = ["proven", "policy", "postgres-direct", "exposed-path", "vercel", "runtime", "graph"] as const;
type LiveSource = (typeof LIVE_SOURCES)[number];

const WHERE: Record<LiveSource, string> = {
  proven: "Reproduced on a disposable replica with synthetic data, never your production database.",
  policy: "Read live from your connected Supabase project.",
  "postgres-direct": "Read live from your connected database.",
  "exposed-path": "Observed from the public internet: ShipLock fetched this from your app's URL without signing in.",
  vercel: "Read live from your Vercel project's settings.",
  runtime: "Observed in your auth logs.",
  // X3: graph paths need two layers (lib/graph/attackPaths.ts), but the route
  // half is code reading alone, so they stay To review.
  graph: "Joined from your code and your connected database. It becomes an issue once your agent proves it with quoted lines or a replica reproduces it.",
};

// What a collector can only report after seeing the exposure itself: a
// content signature in a file anyone can download, a table the anon key
// reads, a secret the host ships to browsers. Row security off is a way in on
// Supabase, whose API serves public tables to the anon key; on plain Postgres
// it is a setting, since nothing serves the table to a stranger.
const OBSERVED_EXPOSURE: Partial<Record<LiveSource, RegExp>> = {
  "exposed-path": /^(exposed:|bundle:shipped_secret:|bundle:source_map_exposed:with_content$|secrets_exposure$)/,
  policy: /^(rls:|unauth_access:|secrets_exposure$|service_role_key$)/,
  vercel: /:client_exposed_secret$/,
};

/** Whether a stored finding came from the live stack rather than the
 * repository. */
export function isLiveSource(source: string): source is LiveSource {
  return (LIVE_SOURCES as readonly string[]).includes(source);
}

/** Confidence and evidence for a live finding: proven from the replica,
 * corroborated when observed, otherwise inferred. */
export function liveEvidence(row: { source: string; finding_id: string }): { confidence: Confidence; attackClass: string; claims: Claim[] } {
  const source = row.source as LiveSource;
  if (source === "proven") {
    return { confidence: "proven", attackClass: "live:proven", claims: [{ claim: WHERE.proven, origin: "live", verified: true }] };
  }
  const observed = OBSERVED_EXPOSURE[source]?.test(row.finding_id) ?? false;
  return {
    confidence: observed ? "corroborated" : "inferred",
    attackClass: `live:${source}`,
    claims: [{ claim: WHERE[source] ?? "Read live from a connected service.", origin: "live", verified: observed }],
  };
}
