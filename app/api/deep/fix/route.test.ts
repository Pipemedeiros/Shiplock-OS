import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";
const getUserMock = vi.fn();
const profileMock = vi.fn();
const runFixPrMock = vi.fn();
const getFixFindingsMock = vi.fn();

vi.mock("@/lib/fixes/prRun", () => ({ runFixPr: runFixPrMock }));
vi.mock("@/lib/fixes/findings", () => ({ getFixFindings: getFixFindingsMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: getUserMock },
    from: () => ({ select: () => ({ eq: () => ({ maybeSingle: profileMock }) }) }),
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
  });

  it("re-resolves the finding instead of trusting client-authored security fields", async () => {
    const res = await POST(req(base.id));
    expect(res.status).toBe(200);
    expect(getFixFindingsMock).toHaveBeenCalledWith("u1");
    expect(runFixPrMock).toHaveBeenCalledWith("u1",{...base,source:"graph"},"-- fix");
  });

  it("rejects an id that is not currently open for this customer", async () => {
    const res = await POST(req("someone-elses-finding"));
    expect(res.status).toBe(404);
    expect(runFixPrMock).not.toHaveBeenCalled();
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
