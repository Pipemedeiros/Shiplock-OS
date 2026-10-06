import type { HotRouteOffer } from "./hotRoutes";

const RANK: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };

/**
 * Cross-layer ordering (Felipe 2026-10-06): a finding on a route customer
 * traffic is hitting hard is marked and shown first within its severity.
 * Traffic never changes a severity; it changes what to look at first.
 */
export function withTraffic<F extends { severity: string; file: string | null; repositoryId: string | null }>(
  findings: readonly F[], hot: Record<string, HotRouteOffer[]>,
): (F & { hitHard: { pattern: string; suspiciousRequests: number } | null })[] {
  return findings
    .map((finding, index) => {
      const route = finding.repositoryId && finding.file ? hot[finding.repositoryId]?.find((h) => h.file === finding.file) : undefined;
      return { finding: { ...finding, hitHard: route ? { pattern: route.pattern, suspiciousRequests: route.suspiciousRequests } : null }, index };
    })
    .sort((a, b) => (RANK[a.finding.severity] ?? 3) - (RANK[b.finding.severity] ?? 3)
      || Number(Boolean(b.finding.hitHard)) - Number(Boolean(a.finding.hitHard)) || a.index - b.index)
    .map(({ finding }) => finding);
}
