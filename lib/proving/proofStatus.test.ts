import { describe, expect, it } from "vitest";
import { proofTable, summarizeProofs } from "./proofStatus";

// The latest proof per finding, as the Risks board shows it.
const auth = (id: string, created: string, finding = "f1", repository = "r1") =>
  ({ id, repository_id: repository, finding_id: finding, created_at: created });

describe("summarizeProofs", () => {
  it("shows the latest consumed authorization's outcome", () => {
    const views = summarizeProofs(
      [auth("a1", "2026-09-24T10:00:00Z"), auth("a2", "2026-09-24T11:00:00Z")],
      [{ authorization_id: "a1", outcome: "reproduced", reason: null }, { authorization_id: "a2", outcome: "ran", reason: null }],
      [],
    );
    expect(views.get("r1|f1")).toEqual({ state: "done", outcome: "ran", reason: null });
  });
  it("is pending while the job has not recorded, and failed if the job died without a record", () => {
    expect(summarizeProofs([auth("a1", "2026-09-24T10:00:00Z")], [], [{ deduplication_key: "proof:a1", status: "running" }]).get("r1|f1"))
      .toEqual({ state: "pending" });
    expect(summarizeProofs([auth("a1", "2026-09-24T10:00:00Z")], [], []).get("r1|f1")).toEqual({ state: "pending" });
    expect(summarizeProofs([auth("a1", "2026-09-24T10:00:00Z")], [], [{ deduplication_key: "proof:a1", status: "dead" }]).get("r1|f1"))
      .toEqual({ state: "failed" });
  });
  it("keys by repository and finding, so the same finding id in two repositories stays separate", () => {
    const views = summarizeProofs([auth("a1", "2026-09-24T10:00:00Z", "f1", "r1"), auth("a2", "2026-09-24T10:00:00Z", "f1", "r2")],
      [{ authorization_id: "a1", outcome: "reproduced", reason: null }], []);
    expect(views.get("r1|f1")).toMatchObject({ outcome: "reproduced" });
    expect(views.get("r2|f1")).toEqual({ state: "pending" });
  });
});

describe("proofTable", () => {
  it("offers a test only for a finding that reaches exactly one plain table", () => {
    expect(proofTable("orders")).toBe("public.orders");
    expect(proofTable(" orders ")).toBe("public.orders");
    expect(proofTable("orders, invoices")).toBeNull();
    expect(proofTable("apiKey")).toBeNull(); // a Prisma model name, not a database table
    expect(proofTable("rpc:use_promo")).toBeNull();
    expect(proofTable(null)).toBeNull();
  });
});

describe("proofOffers (the Risks board's proof panel per finding)", () => {
  const finding = (rowId: string, blastRadius: string | null, repositoryId: string | null = "r1") =>
    ({ rowId, id: `id-${rowId}`, blastRadius, repositoryId });
  it("offers nothing unless the account has proving turned on", async () => {
    const { proofOffers } = await import("./proofStatus");
    expect(proofOffers([finding("1", "orders")], false, new Map())).toEqual({});
  });
  it("offers a single-table finding with its latest outcome, and skips the rest", async () => {
    const { proofOffers } = await import("./proofStatus");
    const offers = proofOffers([finding("1", "orders"), finding("2", "orders, invoices"), finding("3", "orders", null)], true,
      new Map([["r1|id-1", { state: "done" as const, outcome: "ran" as const, reason: null }]]));
    expect(offers).toEqual({ "1": { repositoryId: "r1", findingId: "id-1", table: "public.orders", view: { state: "done", outcome: "ran", reason: null } } });
  });
});
