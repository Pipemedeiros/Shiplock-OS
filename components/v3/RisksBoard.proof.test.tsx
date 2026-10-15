import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => {} }) }));
import { RisksBoard } from "./RisksBoard";
import type { DashboardFinding } from "@/lib/agent/dashboardData";

// Q7: the proof panel appears only on a finding the server offered it for.
const finding: DashboardFinding = {
  rowId: "1", id: "f1", title: "Anyone signed in can read every order", consequence: "c", severity: "CRITICAL",
  confidence: "inferred", attackClass: "missing_ownership", entry: "/api/orders", file: "app/api/orders/route.ts",
  blastRadius: "orders", fixKind: "manual", claims: [], repository: "acme/app", repositoryId: "r1",
  detectedAt: "2026-09-24T00:00:00Z", fixPrUrl: null, fixPrNumber: null, confirmed: true,
};

describe("RisksBoard proof panel (Q7)", () => {
  it("shows the test on a disposable copy when offered", () => {
    const html = renderToStaticMarkup(<RisksBoard findings={[finding]}
      proofs={{ "1": { repositoryId: "r1", findingId: "f1", table: "public.orders", view: null } }} />);
    expect(html).toContain("Test on a disposable copy");
  });
  it("shows nothing about proofs when the account has none offered", () => {
    expect(renderToStaticMarkup(<RisksBoard findings={[finding]} />)).not.toContain("disposable copy");
  });
});

// A1/A2 (Felipe 2026-10-07): a candidate is labelled "To review", and a
// confirmed issue shows its proof, the quoted lines, in the evidence.
describe("RisksBoard candidates and proof", () => {
  it("labels an unconfirmed finding as a candidate to review", () => {
    expect(renderToStaticMarkup(<RisksBoard findings={[{ ...finding, confirmed: false }]} />)).toContain("To review");
    expect(renderToStaticMarkup(<RisksBoard findings={[finding]} />)).not.toContain("To review");
  });
  it("shows the quoted proof lines in the evidence", () => {
    const proven = { ...finding, claims: [{ claim: "Proof, data: app/api/orders/route.ts:12 return db.orders.findMany()", origin: "agent" as const, verified: true }] };
    const html = renderToStaticMarkup(<RisksBoard findings={[proven]} />);
    expect(html).toContain("app/api/orders/route.ts:12");
    expect(html).toContain("Proved");
  });
});

// Strix's proof per finding, run by the founder: one harmless request against
// their own preview app, offered only where one anonymous request shows the gap.
describe("RisksBoard self-check", () => {
  it("offers the request on a route with no sign-in check", () => {
    const open = { ...finding, attackClass: "missing_authentication", entry: "/api/orders/[id]" };
    const html = renderToStaticMarkup(<RisksBoard findings={[open]} />);
    expect(html).toContain("Check it yourself");
    expect(html).toContain("/api/orders/00000000-0000-4000-8000-000000000000");
  });
  it("offers nothing where one request cannot show the gap", () => {
    expect(renderToStaticMarkup(<RisksBoard findings={[finding]} />)).not.toContain("Check it yourself");
  });
});
