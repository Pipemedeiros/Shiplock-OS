import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Felipe (2026-09-30): the customer's own agent should have ShipLock's context
// before it edits: stack, guardrails, open findings, and what was NOT read.
// Read only, PAT authenticated, selected repositories only; no model call.
const s = vi.hoisted(() => ({ auth: vi.fn(), repos: vi.fn(), runs: vi.fn(), findings: vi.fn(), source: vi.fn(), loop: vi.fn() }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: s.auth }));
vi.mock("@/lib/agent/dashboardData", () => ({ getRepositories: s.repos, getRuns: s.runs, getOpenFindings: s.findings }));
vi.mock("@/lib/graph/repositorySource", () => ({ loadRepositoryGraphSource: s.source }));
vi.mock("@/lib/agent/securityLoopData", () => ({ loadSecurityLoopInput: s.loop }));
const { GET } = await import("./route");
const get = (q = "") => GET(new NextRequest(`https://shiplock.dev/api/mcp/context${q}`));
const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: true,
  machineGated: false, usesServiceRole: false, ownershipFiltered: false, identityReadable: true, ownershipReadable: true, dataReadable: true,
  machineGateReadable: true, serviceRoleReadable: true, identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [] };

describe("GET /api/mcp/context", () => {
  beforeEach(() => {
    s.auth.mockReset().mockResolvedValue({ userId: "u" });
    s.repos.mockReset().mockResolvedValue([{ id: "r1", fullName: "acme/app", lastAuditAt: "2026-09-30T00:00:00Z" }]);
    s.runs.mockReset().mockResolvedValue([{ fullName: "acme/app", startedAt: "2026-09-30T00:00:00Z", status: "complete",
      stack: { tools: [{ id: "supabase", name: "Supabase", kind: "database" }] },
      coverage: [{ name: "12 files we did not read", why: "size", effect: "not checked" }] }]);
    s.findings.mockReset().mockResolvedValue([
      { id: "agent:own", repositoryId: "r1", title: "Signed-in callers are not limited to their own rows", severity: "WARNING", entry: "/api/orders",
        file: "app/api/orders/route.ts", consequence: "Any user reads every order.", confidence: "inferred", attackClass: "missing_ownership", fixKind: "manual" },
      { id: "agent:open", repositoryId: "r1", title: "Anyone can read an order by id", severity: "CRITICAL", entry: "/api/orders/[id]",
        file: "app/api/orders/[id]/route.ts", consequence: "Anyone reads any order.", confidence: "proven", attackClass: "missing_authentication", fixKind: "pr", confirmed: true },
      { repositoryId: "other", title: "not this repo", severity: "CRITICAL", entry: null, file: null, consequence: "", confidence: "x" }]);
    s.source.mockReset().mockResolvedValue({ repositoryId: "r1", routes: [route] });
    s.loop.mockReset().mockResolvedValue({ current: null, finished: null, agent: { available: true, paused: "not_connected", pending: 0, answered: 0 },
      map: null, fix: { open: 0, withPr: 0 }, watch: { prChecks: 0, blockedPrs: 0, trafficSites: 0, hotRoutes: 0, providersRead: 0, providersConnected: 0 } });
  });

  // Felipe 2026-10-06: the agent sees the same loop and progress as the
  // dashboard, and a running audit never reads as "nothing unread".
  it("reads notRead from the last finished audit and reports one in progress", async () => {
    s.runs.mockResolvedValue([
      { fullName: "acme/app", startedAt: "2026-10-06T00:00:00Z", status: "running", stack: null, coverage: [], trace: [{ time: "2s", label: "412 files read" }] },
      { fullName: "acme/app", startedAt: "2026-09-30T00:00:00Z", status: "complete", stack: { tools: [] },
        coverage: [{ name: "12 files we did not read", why: "size", effect: "not checked" }], trace: [] }]);
    const body = await (await get("?repository=acme/app")).json();
    expect(body.notRead).toEqual(["12 files we did not read: not checked"]);
    expect(body.lastAudit).toEqual({ at: "2026-09-30T00:00:00Z", status: "complete" });
    expect(body.auditInProgress).toEqual({ status: "running", step: "412 files read" });
  });

  it("serves the security loop the dashboard shows, without links", async () => {
    const body = await (await get("?repository=acme/app")).json();
    expect(body.loop.map((x: { stage: string }) => x.stage)).toEqual(["Read", "Attack", "Map", "Fix", "Watch"]);
    expect(body.loop[0]).toEqual({ stage: "Read", state: "off", headline: "Not audited", detail: expect.any(String) });
  });

  it("refuses without a token", async () => {
    s.auth.mockResolvedValue({ error: new Response(null, { status: 401 }) });
    expect((await get()).status).toBe(401);
  });

  it("returns stack, guardrails, this repository's open findings and what was not read", async () => {
    const body = await (await get("?repository=acme/app")).json();
    expect(body.repository).toBe("acme/app");
    expect(body.stack).toEqual([{ name: "Supabase", kind: "database" }]);
    expect(body.guardrails.rules.map((r: { kind: string }) => r.kind)).toEqual(["requires_signed_in_caller"]);
    expect(body.openFindings).toEqual([
      { id: "agent:own", title: "Signed-in callers are not limited to their own rows", severity: "WARNING", route: "/api/orders",
        file: "app/api/orders/route.ts", consequence: "Any user reads every order.", confirmed: false, fixKind: "manual", selfCheck: null },
      // The id and fix kind feed open_fix_pull_request; the self-check is one harmless request for a preview app.
      { id: "agent:open", title: "Anyone can read an order by id", severity: "CRITICAL", route: "/api/orders/[id]",
        file: "app/api/orders/[id]/route.ts", consequence: "Anyone reads any order.", confirmed: true, fixKind: "pr",
        selfCheck: 'curl -i -X GET "$APP_URL/api/orders/00000000-0000-4000-8000-000000000000"' },
    ]);
    expect(body.howToUse).toMatch(/open_fix_pull_request/);
    expect(body.notRead).toEqual(["12 files we did not read: not checked"]);
    expect(body.howToUse).toMatch(/not known to be safe/);
  });

  it("does not serve an unselected repository and says unknown before any audit", async () => {
    expect((await get("?repository=someone/else")).status).toBe(404);
    s.runs.mockResolvedValue([]); s.source.mockResolvedValue({ repositoryId: "r1" });
    const body = await (await get("?repository=acme/app")).json();
    expect(body.lastAudit).toBeNull();
    expect(body.guardrails).toBeNull();
  });
});
