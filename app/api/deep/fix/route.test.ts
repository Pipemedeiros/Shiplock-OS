import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";
const getUserMock = vi.fn();
const profileMock = vi.fn();
const runFixPrMock = vi.fn();
const getFixFindingsMock = vi.fn();
const requestMock = vi.fn();
const repoMock = vi.fn();

vi.mock("@/lib/fixes/prRun", () => ({ runFixPr: runFixPrMock }));
vi.mock("@/lib/fixes/findings", () => ({ getFixFindings: getFixFindingsMock }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestRepairAction: requestMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: getUserMock },
    from: (table: string) => table === "repositories"
      ? { select: () => ({ eq: () => ({ eq: repoMock }) }) }
      : { select: () => ({ eq: () => ({ maybeSingle: profileMock }) }) },
  }),
}));

const { POST } = await import("./route");

function req(findingId: string) {
  return new NextRequest("https://shiplock.dev/api/deep/fix", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer t" },
    body: JSON.stringify({ findingId, editedContent: "-- fix" }),
  });
}

const base = {
  id: "path:anon_route_unprotected_table",
  title: "Orders readable across tenants",
  severity: "CRITICAL",
  fix: "alter table orders enable row level security;",
};

describe("POST /api/deep/fix — server-owned finding", () => {
  beforeEach(() => {
    getUserMock.mockReset().mockResolvedValue({ data: { user: { id: "u1" } } });
    profileMock.mockReset().mockResolvedValue({ data: { is_paid: true } });
    runFixPrMock.mockReset().mockResolvedValue({ url: "https://github.com/x/y/pull/1" });
    getFixFindingsMock.mockReset().mockResolvedValue([{...base,source:"graph"}]);
    repoMock.mockReset().mockResolvedValue({ data: [{ id: "repo-1", full_name: "acme/app" }], error: null });
    requestMock.mockReset().mockResolvedValue("receipt-1");
  });

  it("re-resolves the finding and admits a receipt instead of opening the PR inline", async () => {
    const res = await POST(req(base.id));
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ receiptId: "receipt-1", status: "queued" });
    expect(getFixFindingsMock).toHaveBeenCalledWith("u1");
    expect(requestMock).toHaveBeenCalledWith({ userId: "u1", repositoryId: "repo-1", action: "finding-fix-pr", findingId: base.id, editedContent: "-- fix" });
    expect(runFixPrMock).not.toHaveBeenCalled();
  });

  it("uses the repository named in a repository-scoped finding id", async () => {
    repoMock.mockResolvedValue({ data: [{ id: "repo-1", full_name: "acme/app" }, { id: "repo-2", full_name: "acme/web" }], error: null });
    getFixFindingsMock.mockResolvedValue([{ ...base, id: "acme/web::path:x", source: "graph" }]);
    await POST(req("acme/web::path:x"));
    expect(requestMock.mock.calls[0][0]).toMatchObject({ repositoryId: "repo-2" });
  });

  it("asks the customer to choose when the repository is ambiguous", async () => {
    repoMock.mockResolvedValue({ data: [{ id: "repo-1", full_name: "acme/app" }, { id: "repo-2", full_name: "acme/web" }], error: null });
    const res = await POST(req(base.id));
    expect(res.status).toBe(409);
    expect(requestMock).not.toHaveBeenCalled();
  });

  it("queues a dependency finding as one bump PR for its repository", async () => {
    getFixFindingsMock.mockResolvedValue([{ ...base, id: "github:dep:left-pad:GHSA-x", source: "github" }]);
    const res = await POST(req("github:dep:left-pad:GHSA-x"));
    expect(res.status).toBe(202);
    expect(requestMock).toHaveBeenCalledWith({ userId: "u1", repositoryId: "repo-1", action: "dependency-bump-pr", findingId: null, editedContent: null });
  });

  it("rejects an id that is not currently open for this customer", async () => {
    const res = await POST(req("someone-elses-finding"));
    expect(res.status).toBe(404);
    expect(requestMock).not.toHaveBeenCalled();
  });

  it("still requires auth before doing anything", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    const res = await POST(req(base.id));
    expect(res.status).toBe(401);
    expect(runFixPrMock).not.toHaveBeenCalled();
  });

  it("still requires an account the database knows about", async () => {
    // Billing is parked, so is_paid no longer decides this. Opening a pull
    // request against someone's repository is not something a caller without a
    // profile row gets to do.
    profileMock.mockResolvedValue({ data: null });
    const res = await POST(req(base.id));
    expect(res.status).toBe(402);
    expect(runFixPrMock).not.toHaveBeenCalled();
  });
});
