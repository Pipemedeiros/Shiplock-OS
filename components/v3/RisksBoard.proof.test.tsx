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
  detectedAt: "2026-09-24T00:00:00Z", fixPrUrl: null, fixPrNumber: null,
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
