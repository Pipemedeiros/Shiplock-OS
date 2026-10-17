import { describe, expect, it } from "vitest";
import { evidenceChain, orderByChain, type ChainFinding } from "./evidenceChain";

const base: ChainFinding = {
  severity: "CRITICAL", confidence: "inferred", attackClass: "missing_authentication", entry: "/api/notes/[id]",
  claims: [], confirmed: false,
};
const proven: ChainFinding = { ...base, confidence: "proven", confirmed: true,
  claims: [{ claim: "Reproduced on a disposable replica", origin: "live", verified: true }] };
const quoted: ChainFinding = { ...base, confidence: "corroborated", confirmed: true,
  claims: [{ claim: "No session check before the query (lines 4 to 9)", origin: "agent", verified: true }] };

const link = (chain: ReturnType<typeof evidenceChain>, id: string) => chain.links.find((l) => l.id === id)!;

describe("the evidence chain: what joins the layers for one finding", () => {
  it("marks the gap met only for a confirmed finding, and names the next step for a candidate", () => {
    const candidate = evidenceChain(base, { trafficConnected: false });
    expect(link(candidate, "gap").state).toBe("open");
    expect(candidate.next).toMatch(/agent/);
    expect(link(evidenceChain(quoted, { trafficConnected: false }), "gap").state).toBe("met");
  });

  it("counts reach when the app's own code calls the route, and never lowers anything when it does not", () => {
    const called = evidenceChain(quoted, { calledBy: ["components/Note.tsx"], trafficConnected: false });
    expect(link(called, "reach")).toMatchObject({ state: "met" });
    expect(link(called, "reach").evidence).toContain("components/Note.tsx");
    const uncalled = evidenceChain(quoted, { calledBy: [], trafficConnected: false });
    // Measured: entries nothing calls were still real 85% of the time.
    expect(link(uncalled, "reach").state).toBe("unknown");
    expect(link(uncalled, "reach").evidence).toMatch(/directly/);
  });

  // P5: what the live site's JavaScript calls is an observation, not an inference.
  it("counts reach observed in the live site's JavaScript, ahead of the repository's own calls", () => {
    const live = evidenceChain(quoted, { calledBy: ["components/Note.tsx"], trafficConnected: false,
      live: { host: "app.acme.com", path: "/api/notes/", observedAt: "2026-10-17T10:00:00.000Z" } });
    expect(link(live, "reach").state).toBe("met");
    expect(link(live, "reach").evidence).toBe("Your live site at app.acme.com ships JavaScript that names /api/notes/, so its address reaches every visitor. ShipLock read it without signing in on 2026-10-17.");
  });

  it("counts reach observed from the public internet", () => {
    const outside = evidenceChain({ ...quoted, attackClass: "live:exposed-path" }, { trafficConnected: false });
    expect(link(outside, "reach").state).toBe("met");
  });

  it("offers the self-check as the open proof step, and marks a replica reproduction met", () => {
    const open = evidenceChain(quoted, { trafficConnected: false });
    expect(link(open, "proof").state).toBe("open");
    expect(link(open, "proof").evidence).toMatch(/curl -i -X GET/);
    expect(open.next).toMatch(/preview/);
    expect(link(evidenceChain(proven, { trafficConnected: false }), "proof").state).toBe("met");
    // An authorization gap needs a second account: no one-request check.
    expect(link(evidenceChain({ ...quoted, attackClass: "missing_authorization" }, { trafficConnected: false }), "proof").state).toBe("unknown");
  });

  // 107: the customer's agent ran the self-check and reported the status.
  // Untrusted agent output: the link stays open (never met, never proof),
  // the evidence says what was reported, and a 401 asks for a re-verify.
  it("shows the agent's reported self-check on the proof link, never as proof", () => {
    const reached = evidenceChain(quoted, { trafficConnected: false,
      selfCheck: { status: 404, host: "localhost:3000", reportedAt: "2026-10-17T12:00:00.000Z" } });
    expect(link(reached, "proof")).toEqual({ id: "proof", title: "It was reproduced", state: "open",
      evidence: "Your agent ran the check on localhost:3000 on 2026-10-17 and reported 404: the route reached the data layer without a sign-in check. Reported by your agent; ShipLock did not send it." });
    expect(reached.next).toMatch(/Fix it/);
    const refused = evidenceChain(quoted, { trafficConnected: false,
      selfCheck: { status: 401, host: "preview.acme.dev", reportedAt: "2026-10-17T12:00:00.000Z" } });
    expect(link(refused, "proof").state).toBe("open");
    expect(refused.next).toMatch(/re-verify/);
    // A proven finding keeps its replica proof; a report never replaces it.
    expect(link(evidenceChain(proven, { trafficConnected: false, selfCheck: { status: 401, host: "localhost", reportedAt: null } }), "proof").state).toBe("met");
  });

  it("reads pressure from traffic: attempts seen, watched and quiet, or not connected", () => {
    expect(link(evidenceChain(quoted, { trafficConnected: true, hitHard: { pattern: "/api/notes/:id", suspiciousRequests: 42 } }), "pressure"))
      .toMatchObject({ state: "met" });
    const quiet = link(evidenceChain(quoted, { trafficConnected: true }), "pressure");
    expect(quiet.state).toBe("open");
    expect(quiet.evidence).not.toMatch(/safe|secure/i);
    expect(link(evidenceChain(quoted, { trafficConnected: false }), "pressure").state).toBe("unknown");
  });

  it("counts met links and writes plain copy with no dashes", () => {
    const full = evidenceChain(proven, { calledBy: ["app/notes/page.tsx"], trafficConnected: true,
      hitHard: { pattern: "/api/notes/:id", suspiciousRequests: 3 } });
    expect(full.met).toBe(4);
    for (const l of full.links) expect(l.evidence).not.toMatch(/[–—]| - /);
    expect(full.next).toBeNull();
  });

  it("orders by severity, then confirmed, then more links met, keeping input order on ties", () => {
    const a = { ...quoted, id: "a" };
    const b = { ...quoted, id: "b" };
    const c = { ...base, id: "c" };
    const w = { ...proven, severity: "WARNING" as const, id: "w" };
    const ordered = orderByChain([w, c, a, b], (f) => (f.id === "b" ? { calledBy: ["x.tsx"], trafficConnected: false } : { trafficConnected: false }));
    expect(ordered.map((f) => f.id)).toEqual(["b", "a", "c", "w"]);
  });
});
