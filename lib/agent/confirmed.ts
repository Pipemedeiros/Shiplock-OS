import { OPEN_BY_DESIGN, type Claim, type Confidence } from "./findings";
import type { Severity } from "@/lib/types";

/**
 * Whether a finding is a confirmed issue (Felipe 2026-10-07: "prioritize
 * accuracy"; AGENTS.md "Attack, not a passive scan"). Only confirmed issues
 * set the status (Exposed, At risk); the rest is "To review". On CORPUS-5's
 * whole harness, findings the customer's agent proved with quoted lines were
 * 71% strictly true and code-pattern findings 0 of 14.
 *
 * Confirmed: a replica proof, a live provider fact, quoted-line proof from the
 * agent (a verified agent claim), or a committed live credential (direct
 * evidence, CRITICAL only after the live-credential rule).
 *
 * Not confirmed: an open-access finding in an app whose own code says it signs
 * no one in by design. It stays, with its proof, as To review.
 */
export function isConfirmed(f: { severity: Severity; confidence: Confidence; attackClass: string; claims: readonly Claim[] }): boolean {
  if (f.attackClass !== "committed_secret" && f.claims.some((c) => c.origin === "routes" && c.claim.startsWith(OPEN_BY_DESIGN))) return false;
  if (f.confidence === "proven") return true;
  if (f.claims.some((c) => c.verified && (c.origin === "agent" || c.origin === "live"))) return true;
  return f.attackClass === "committed_secret" && f.severity === "CRITICAL";
}
