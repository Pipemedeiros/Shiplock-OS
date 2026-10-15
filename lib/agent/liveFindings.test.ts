import { describe, expect, it } from "vitest";
import { LIVE_SOURCES, liveEvidence } from "./liveFindings";
import { isConfirmed } from "./confirmed";

// W3 (G3, G4): findings ShipLock observed outside the repository were stored
// but never reached Issues or the status, because the open-findings read took
// source 'agent' only, and the rows carry no claims or confidence. A replica
// proof, a key downloaded from the shipped bundle, and row security read off
// are the strongest evidence the product has.
const row = (source: string, finding_id: string, severity = "CRITICAL") => ({ source, finding_id, severity });
const confirmed = (r: ReturnType<typeof row>) => {
  const e = liveEvidence(r);
  return isConfirmed({ severity: r.severity as never, ...e });
};

describe("live findings", () => {
  it("reads every collector that observes outside the repository", () => {
    expect([...LIVE_SOURCES].sort()).toEqual(["exposed-path", "policy", "postgres-direct", "proven", "runtime", "vercel"]);
  });

  it("confirms a replica proof as proven", () => {
    expect(liveEvidence(row("proven", "proof:rls:orders")).confidence).toBe("proven");
    expect(confirmed(row("proven", "proof:rls:orders"))).toBe(true);
  });

  it.each([
    ["exposed-path", "bundle:shipped_secret:supabase_service_role_jwt"],
    ["exposed-path", "exposed:git_exposed"],
    ["exposed-path", "bundle:source_map_exposed:with_content"],
    ["policy", "rls:orders"],
    ["policy", "unauth_access:orders"],
    ["vercel", "vercel:web:NEXT_PUBLIC_SECRET_TOKEN:client_exposed_secret"],
  ])("confirms a direct observation of exposure (%s %s)", (source, id) => {
    const e = liveEvidence(row(source, id));
    expect(e.claims).toEqual([expect.objectContaining({ origin: "live", verified: true })]);
    expect(confirmed(row(source, id))).toBe(true);
  });

  it.each([
    ["exposed-path", "email_auth:dmarc_missing"],
    ["exposed-path", "origin:no_edge_protection"],
    ["exposed-path", "bundle:source_map_exposed:paths_only"],
    ["policy", "storage:no_pitr"],
    ["policy", "extensions:in_public_schema"],
    ["postgres-direct", "rls:orders"],
    ["runtime", "auth:burst"],
  ])("keeps a setting that weakens a layer as To review (%s %s)", (source, id) => {
    expect(confirmed(row(source, id, "WARNING"))).toBe(false);
  });

  it("says where each was read, in plain words without dashes", () => {
    for (const source of LIVE_SOURCES) {
      const [claim] = liveEvidence(row(source, "x")).claims;
      expect(claim.claim.length).toBeGreaterThan(10);
      expect(claim.claim).not.toMatch(/[–—]/);
    }
    expect(liveEvidence(row("exposed-path", "exposed:git_exposed")).claims[0].claim)
      .toBe("Observed from the public internet: ShipLock fetched this from your app's URL without signing in.");
  });
});
