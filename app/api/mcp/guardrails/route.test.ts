import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// The customer's coding agent reads the same guardrails
// the PR check enforces, for a repository the customer selected, over a PAT.
const authMcp = vi.fn();
const repos = vi.fn();
const source = vi.fn();
vi.mock("@/lib/mcpAuth", () => ({ authMcp }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: () => ({ select: () => ({ eq: () => ({ eq: repos }) }) }) }),
}));
vi.mock("@/lib/graph/repositorySource", () => ({ loadRepositoryGraphSource: source }));

const { GET } = await import("./route");
const get = (query = "") => GET(new NextRequest(`https://shiplock.dev/api/mcp/guardrails${query}`));
const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: true,
  machineGated: false, usesServiceRole: false, ownershipFiltered: true, identityReadable: true, ownershipReadable: true, dataReadable: true,
  machineGateReadable: true, serviceRoleReadable: true, identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [] };

describe("GET /api/mcp/guardrails", () => {
  beforeEach(() => {
    authMcp.mockReset().mockResolvedValue({ userId: "u" });
    repos.mockReset().mockResolvedValue({ data: [{ id: "r1", full_name: "acme/app" }], error: null });
    source.mockReset().mockResolvedValue({ repositoryId: "r1", sourceCoverage: "partial", routes: [route] });
  });

  it("refuses without a valid token", async () => {
    authMcp.mockResolvedValue({ error: new Response(null, { status: 401 }) });
    expect((await get()).status).toBe(401);
  });

  it("returns the selected repository's rules from observed facts", async () => {
    const body = await (await get("?repository=acme/app")).json();
    expect(source).toHaveBeenCalledWith("u", "r1");
    expect(body.guardrails.rules.map((r: { kind: string }) => r.kind)).toEqual(["requires_signed_in_caller", "scopes_rows_to_caller"]);
    expect(body.coverage).toMatch(/not rules/);
  });

  it("uses the only selected repository when none is named, and asks when there are several", async () => {
    expect((await get()).status).toBe(200);
    repos.mockResolvedValue({ data: [{ id: "r1", full_name: "acme/app" }, { id: "r2", full_name: "acme/web" }], error: null });
    const res = await get();
    expect(res.status).toBe(400);
    expect((await res.json()).repositories).toEqual(["acme/app", "acme/web"]);
  });

  it("does not serve a repository the customer did not select", async () => {
    expect((await get("?repository=someone/else")).status).toBe(404);
  });

  it("says unknown rather than returning an empty rule set when no audit facts exist", async () => {
    source.mockResolvedValue({ repositoryId: "r1", sourceCoverage: "unknown" });
    const body = await (await get("?repository=acme/app")).json();
    expect(body.guardrails).toBeNull();
    expect(body.coverage).toMatch(/No audit/);
  });
});
