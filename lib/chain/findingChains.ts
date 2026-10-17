import { liveCaller } from "@/lib/security/shippedCalls";
import { evidenceChain, type Chain, type ChainFinding } from "./evidenceChain";
import type { LiveReach } from "./liveReach";

/**
 * Each open finding's evidence chain for the dashboard, the same one the
 * agent reads over MCP (app/api/mcp/context). Reach comes from the newest
 * stored route facts of the finding's repository (runs arrive newest first);
 * pressure from attack traffic already joined to the finding
 * (lib/traffic/findingTraffic.ts); live reach only for the repository the
 * founder bound the app address to (lib/chain/liveReach.ts). Nothing here
 * changes a status.
 */
type Run = { fullName: string; routeFacts: { path: string; calledBy?: string[] }[] | null };
type Repo = { id: string; fullName: string };
type Hit = { pattern: string; suspiciousRequests: number } | null | undefined;

export function withChains<F extends ChainFinding & { repositoryId: string | null; hitHard?: Hit }>(
  findings: readonly F[], input: { runs: readonly Run[]; repos: readonly Repo[]; trafficConnected: boolean; live?: LiveReach | null },
): (F & { chain: Chain })[] {
  const nameOf = new Map(input.repos.map((r) => [r.id, r.fullName]));
  const reach = new Map<string, Map<string, string[]>>();
  for (const run of input.runs) {
    if (!run.routeFacts || reach.has(run.fullName)) continue;
    reach.set(run.fullName, new Map(run.routeFacts.map((r) => [r.path, r.calledBy ?? []])));
  }
  return findings.map((f) => {
    const facts = f.repositoryId ? reach.get(nameOf.get(f.repositoryId) ?? "") : undefined;
    return { ...f, chain: evidenceChain(f, {
      calledBy: f.entry ? facts?.get(f.entry) : undefined, live: liveContext(f, input.live),
      trafficConnected: input.trafficConnected, hitHard: f.hitHard ?? null,
    }) };
  });
}

/** The live path naming this finding's entry, for its bound repository only. */
export function liveContext(f: { repositoryId: string | null; entry: string | null }, live: LiveReach | null | undefined) {
  if (!live || !f.entry || f.repositoryId !== live.repositoryId) return null;
  const path = liveCaller(f.entry, live.paths);
  return path ? { host: live.host, path, observedAt: live.observedAt } : null;
}
