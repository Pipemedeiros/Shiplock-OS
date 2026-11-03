import { liveCaller } from "@/lib/security/shippedCalls";
import { checkMethods } from "@/lib/proof/selfCheck";
import { evidenceChain, type Chain, type ChainFinding } from "./evidenceChain";
import type { LiveReach } from "./liveReach";
import type { SelfCheckReport } from "@/lib/proof/selfCheckReports";

/**
 * Each open finding's evidence chain for the dashboard, the same one the
 * agent reads over MCP (app/api/mcp/context). Reach comes from the newest
 * stored route facts of the finding's repository (runs arrive newest first);
 * pressure from attack traffic already joined to the finding
 * (lib/traffic/findingTraffic.ts); live reach only for the repository the
 * founder bound the app address to (lib/chain/liveReach.ts). Nothing here
 * changes a status.
 */
type RouteFacts = { path: string; calledBy?: string[]; methods?: string[]; unrefusedMethods?: string[] };
type Run = { fullName: string; routeFacts: RouteFacts[] | null };
type Repo = { id: string; fullName: string };
type Hit = { pattern: string; suspiciousRequests: number } | null | undefined;

/** Attaches to each finding its route's methods and its evidence chain, from
 * the latest audit facts. */
export function withChains<F extends ChainFinding & { repositoryId: string | null; rowId?: string; hitHard?: Hit }>(
  findings: readonly F[], input: { runs: readonly Run[]; repos: readonly Repo[]; trafficConnected: boolean; live?: LiveReach | null;
    reports?: ReadonlyMap<string, SelfCheckReport> },
): (F & { methods: string[]; chain: Chain })[] {
  const nameOf = new Map(input.repos.map((r) => [r.id, r.fullName]));
  const facts = latestRouteFacts(input.runs);
  return findings.map((f) => {
    const route = f.entry && f.repositoryId ? facts.get(nameOf.get(f.repositoryId) ?? "")?.get(f.entry) : undefined;
    const withMethods = { ...f, methods: checkMethods(route) };
    return { ...withMethods, chain: evidenceChain(withMethods, {
      calledBy: route ? route.calledBy ?? [] : undefined, live: liveContext(f, input.live),
      selfCheck: (f.rowId && input.reports?.get(f.rowId)) || null,
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

/** Each repository's newest stored route facts, by path (runs arrive newest first). */
export function latestRouteFacts(runs: readonly Run[]): Map<string, Map<string, RouteFacts>> {
  const out = new Map<string, Map<string, RouteFacts>>();
  for (const run of runs) {
    if (!run.routeFacts || out.has(run.fullName)) continue;
    out.set(run.fullName, new Map(run.routeFacts.map((r) => [r.path, r])));
  }
  return out;
}
