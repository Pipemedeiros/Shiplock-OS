export type TrafficHit = { pattern: string; suspiciousRequests: number };

/** A finding on a route customer traffic is hitting hard (cross-layer). */
export function HitHard({ hit }: { hit: TrafficHit }) {
  const evidence = `${hit.suspiciousRequests.toLocaleString("en-US")} suspicious requests observed on ${hit.pattern}`;
  return <span className="v3-tag warn" title={evidence} aria-label={`Hit hard: ${evidence}`}>Hit hard</span>;
}
