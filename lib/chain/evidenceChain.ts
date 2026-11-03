import type { Claim, Confidence } from "@/lib/agent/findings";
import { readSelfCheck, selfCheck } from "@/lib/proof/selfCheck";
import type { Severity } from "@/lib/types";

/**
 * The evidence chain: one finding, read the way an attacker works through it
 * (reconnaissance, the weakness, exploitation, and someone actually trying),
 * with each link taken from a different layer ShipLock already reads.
 *
 *   reach     can a stranger get to it: the live site's JavaScript names it
 *             (lib/chain/liveReach.ts), the app's own code calls the entry
 *             (lib/graph/clientReach.ts), or it was fetched from the public URL
 *   gap       the weakness is confirmed: quoted lines the verifier accepted,
 *             a live fact, or a replica (lib/agent/confirmed.ts)
 *   proof     it was reproduced: a replica run; otherwise the one harmless
 *             request the founder or their agent can run (lib/proof/selfCheck.ts)
 *   pressure  someone is trying it now: attack traffic on that route
 *             (lib/traffic/hotRoutes.ts)
 *
 * The chain never sets or lowers a status; isConfirmed still does. It orders
 * what to fix first and names the next safe step for the founder and for
 * their agent over MCP. A link that was not read is "unknown", never met and
 * never cleared: absence is not "checked and absent" (AGENTS.md, Evidence).
 */
export type ChainFinding = {
  severity: Severity; confidence: Confidence; attackClass: string; entry: string | null;
  claims: readonly Claim[]; confirmed: boolean;
  /** Methods for the self-check, from the audit's route facts (checkMethods). */
  methods?: readonly string[];
};
export type ChainContext = {
  /** Shipped files that call the entry, from the audit's stored route facts. */
  calledBy?: readonly string[];
  /** The live site's JavaScript names the entry, under the founder's binding. */
  live?: { host: string; path: string; observedAt: string | null } | null;
  /** A traffic snippet reports for this account. */
  trafficConnected: boolean;
  /** The self-check the customer's agent ran and reported (migration 107). */
  selfCheck?: { status: number; host: string; reportedAt: string | null } | null;
  /** Attack traffic on the finding's route (lib/traffic/findingTraffic.ts). */
  hitHard?: { pattern: string; suspiciousRequests: number } | null;
};
type LinkId = "reach" | "gap" | "proof" | "pressure";
/** reported: the evidence is the customer's agent's own report (still open). */
export type Link = { id: LinkId; title: string; state: "met" | "open" | "unknown"; evidence: string; reported?: true };
export type Chain = { links: Link[]; met: number; next: string | null };

const RANK: Record<string, number> = { CRITICAL: 0, WARNING: 1, INFO: 2 };

function reach(f: ChainFinding, ctx: ChainContext): Link {
  const title = "A stranger can reach it";
  if (f.attackClass === "live:exposed-path") {
    return { id: "reach", title, state: "met", evidence: "ShipLock fetched it from your public URL without signing in." };
  }
  if (ctx.live) {
    const on = ctx.live.observedAt ? ` on ${ctx.live.observedAt.slice(0, 10)}` : "";
    return { id: "reach", title, state: "met",
      evidence: `Your live site at ${ctx.live.host} ships JavaScript that names ${ctx.live.path}, so its address reaches every visitor. ShipLock read it without signing in${on}.` };
  }
  if (ctx.calledBy && ctx.calledBy.length > 0) {
    return { id: "reach", title, state: "met", evidence: `Your app calls it from ${ctx.calledBy.slice(0, 3).join(", ")}, so its address ships to every visitor.` };
  }
  return { id: "reach", title, state: "unknown",
    evidence: "Nothing your app ships points at it. Attackers can still call it directly, so this does not lower the finding." };
}

function gap(f: ChainFinding): Link {
  const title = "The check is missing";
  if (!f.confirmed) {
    return { id: "gap", title, state: "open", evidence: "A candidate: your agent has not yet proven it with quoted lines, and nothing live confirms it." };
  }
  const source = f.confidence === "proven" ? "Reproduced on a disposable replica."
    : f.claims.some((c) => c.verified && c.origin === "live") ? "Confirmed by a live fact ShipLock read."
      : "Proven with quoted lines that ShipLock checked against your code.";
  return { id: "gap", title, state: "met", evidence: source };
}

function proof(f: ChainFinding, ctx: ChainContext): Link {
  const title = "It was reproduced";
  if (f.confidence === "proven") return { id: "proof", title, state: "met", evidence: "Reproduced on a disposable replica with synthetic data, never your production database." };
  // A test the agent ran is reported, not observed: the link stays open.
  if (ctx.selfCheck) {
    const { status, host, reportedAt } = ctx.selfCheck;
    const on = reportedAt ? ` on ${reportedAt.slice(0, 10)}` : "";
    return { id: "proof", title, state: "open", reported: true,
      evidence: `Your agent ran the check on ${host}${on} and reported ${status}: ${readSelfCheck(status).meaning}. Reported by your agent; ShipLock did not send it.` };
  }
  const check = f.entry ? selfCheck({ entry: f.entry, attackClass: f.attackClass, methods: f.methods ? [...f.methods] : undefined }) : null;
  if (check) return { id: "proof", title, state: "open", evidence: `Not yet. One harmless request against your preview app shows it: ${check.curl}` };
  return { id: "proof", title, state: "unknown", evidence: "No safe one-request check exists for this kind of issue; it needs a second account or a replica." };
}

function pressure(ctx: ChainContext): Link {
  const title = "Someone is trying it";
  if (ctx.hitHard) {
    return { id: "pressure", title, state: "met",
      evidence: `${ctx.hitHard.suspiciousRequests} suspicious requests hit ${ctx.hitHard.pattern} recently.` };
  }
  if (ctx.trafficConnected) return { id: "pressure", title, state: "open", evidence: "Your traffic is watched and no attempt on this route was seen yet." };
  return { id: "pressure", title, state: "unknown", evidence: "Traffic is not connected, so attempts on this route are not seen." };
}

/** The four links behind a finding (reach, gap, proof, pressure), how many are
 * met, and the next safe action. */
export function evidenceChain(f: ChainFinding, ctx: ChainContext): Chain {
  const links = [reach(f, ctx), gap(f), proof(f, ctx), pressure(ctx)];
  const met = links.filter((l) => l.state === "met").length;
  const g = links[1], p = links[2];
  const outcome = ctx.selfCheck && f.confidence !== "proven" ? readSelfCheck(ctx.selfCheck.status).outcome : null;
  const next = g.state !== "met" ? "Ask your agent to prove or refute it with quoted lines."
    : outcome === "reached" ? "Fix it: the check your agent ran reached the data layer without a sign-in check."
      : outcome === "check_ran" ? "Your agent's check met a sign-in check there. Ask it to re-verify the quoted lines against that build."
        : p.state === "open" ? "Run the one harmless request on your preview app, or ask your agent to, and compare the status."
          : null;
  return { links, met, next };
}

/** Severity first, then confirmed issues, then more links met; stable on ties. */
export function orderByChain<F extends ChainFinding>(findings: readonly F[], contextOf: (f: F) => ChainContext): F[] {
  return findings
    .map((f, index) => ({ f, index, met: evidenceChain(f, contextOf(f)).met }))
    .sort((a, b) => (RANK[a.f.severity] ?? 3) - (RANK[b.f.severity] ?? 3)
      || Number(b.f.confirmed) - Number(a.f.confirmed) || b.met - a.met || a.index - b.index)
    .map(({ f }) => f);
}
