import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// Felipe (2026-09-30): the customer's own agent should have ShipLock's context
// before it edits: stack, guardrails, open findings, and what was NOT read.
// Read only, PAT authenticated, selected repositories only; no model call.
const s = vi.hoisted(() => ({ auth: vi.fn(), repos: vi.fn(), runs: vi.fn(), findings: vi.fn(), source: vi.fn(), loop: vi.fn(), hot: vi.fn(), live: vi.fn(), reports: vi.fn() }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: s.auth }));
vi.mock("@/lib/agent/dashboardData", () => ({ getRepositories: s.repos, getRuns: s.runs, getOpenFindings: s.findings }));
vi.mock("@/lib/graph/repositorySource", () => ({ loadRepositoryGraphSource: s.source }));
vi.mock("@/lib/agent/securityLoopData", () => ({ loadSecurityLoopInput: s.loop }));
vi.mock("@/lib/traffic/hotRoutes", () => ({ getHotRoutes: s.hot }));
vi.mock("@/lib/chain/liveReach", () => ({ loadLiveReach: s.live }));
vi.mock("@/lib/proof/selfCheckReports", () => ({ loadSelfCheckReports: s.reports }));
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
    s.hot.mockReset().mockResolvedValue({});
    s.live.mockReset().mockResolvedValue(null);
    s.reports.mockReset().mockResolvedValue(new Map());
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
    // Critical and confirmed first (the evidence chain's order); the chain itself is checked below.
    const withoutChain = (f: Record<string, unknown>) => Object.fromEntries(Object.entries(f).filter(([k]) => k !== "chain"));
    expect(body.openFindings.map(withoutChain)).toEqual([
      // The id and fix kind feed open_fix_pull_request; the self-check is one harmless request for a preview app.
      { id: "agent:open", title: "Anyone can read an order by id", severity: "CRITICAL", route: "/api/orders/[id]",
        file: "app/api/orders/[id]/route.ts", consequence: "Anyone reads any order.", confirmed: true, fixKind: "pr",
        selfCheck: 'curl -i -X GET "$APP_URL/api/orders/00000000-0000-4000-8000-000000000000"' },
      { id: "agent:own", title: "Signed-in callers are not limited to their own rows", severity: "WARNING", route: "/api/orders",
        file: "app/api/orders/route.ts", consequence: "Any user reads every order.", confirmed: false, fixKind: "manual", selfCheck: null },
    ]);
    expect(body.howToUse).toMatch(/open_fix_pull_request/);
    expect(body.notRead).toEqual(["12 files we did not read: not checked"]);
    expect(body.howToUse).toMatch(/not known to be safe/);
  });

  // The evidence chain: each finding tells the agent which layers back it and the next safe step.
  it("gives each finding its evidence chain: reach from stored route facts, pressure from attack traffic", async () => {
    s.runs.mockResolvedValue([{ fullName: "acme/app", startedAt: "2026-09-30T00:00:00Z", status: "complete", stack: null, coverage: [],
      routeFacts: [{ path: "/api/orders/[id]", file: "app/api/orders/[id]/route.ts", tables: [], authenticated: false, ownershipFiltered: false,
        machineGated: false, calledBy: ["components/OrderView.tsx"] }] }]);
    s.loop.mockResolvedValue({ current: null, finished: null, agent: { available: true, paused: "not_connected", pending: 0, answered: 0 },
      map: null, fix: { open: 0, withPr: 0 }, watch: { prChecks: 0, blockedPrs: 0, trafficSites: 1, hotRoutes: 1, providersRead: 0, providersConnected: 0 } });
    s.hot.mockResolvedValue({ r1: [{ file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 31 }] });
    const body = await (await get("?repository=acme/app")).json();
    const open = body.openFindings.find((f: { id: string }) => f.id === "agent:open");
    expect(open.chain.links.map((l: { link: string; state: string }) => `${l.link}:${l.state}`))
      .toEqual(["reach:met", "gap:met", "proof:met", "pressure:met"]);
    expect(open.chain.links[0].evidence).toContain("components/OrderView.tsx");
    expect(open.chain.next).toBeNull();
    const own = body.openFindings.find((f: { id: string }) => f.id === "agent:own");
    expect(own.chain.links.map((l: { link: string; state: string }) => `${l.link}:${l.state}`))
      .toEqual(["reach:unknown", "gap:open", "proof:unknown", "pressure:open"]);
    expect(own.chain.next).toMatch(/quoted lines/);
  });

  // P5: the live site's JavaScript, under the founder's binding to this repository.
  it("tells the agent when the live site calls a finding's route, for the bound repository only", async () => {
    s.live.mockResolvedValue({ repositoryId: "r1", host: "app.acme.com", observedAt: "2026-10-17T10:00:00.000Z", paths: ["/api/orders/"] });
    const body = await (await get("?repository=acme/app")).json();
    const open = body.openFindings.find((f: { id: string }) => f.id === "agent:open");
    expect(open.chain.links[0]).toMatchObject({ link: "reach", state: "met" });
    expect(open.chain.links[0].evidence).toContain("live site at app.acme.com");
    s.live.mockResolvedValue({ repositoryId: "r2", host: "app.acme.com", observedAt: null, paths: ["/api/orders/"] });
    const other = (await (await get("?repository=acme/app")).json()).openFindings.find((f: { id: string }) => f.id === "agent:open");
    expect(other.chain.links[0].state).toBe("unknown");
    s.live.mockRejectedValue(new Error("down"));
    expect((await get("?repository=acme/app")).status).toBe(200);
  });

  // 107: the agent sees its own reported self-check on the finding, and the next step it implies.
  it("returns the agent's reported self-check on the finding's proof link", async () => {
    s.findings.mockResolvedValue([{ id: "agent:notes", rowId: "row-1", repositoryId: "r1", title: "t", severity: "CRITICAL", entry: "/api/notes/[id]",
      file: "app/api/notes/[id]/route.ts", consequence: "c", confidence: "corroborated", attackClass: "missing_authentication", fixKind: "pr", confirmed: true,
      claims: [{ claim: "quoted", origin: "agent", verified: true }] }]);
    s.reports.mockResolvedValue(new Map([["row-1", { status: 404, host: "localhost:3000", reportedAt: "2026-10-17T12:00:00.000Z" }]]));
    const [f] = (await (await get("?repository=acme/app")).json()).openFindings;
    expect(f.chain.links[2]).toMatchObject({ link: "proof", state: "open" });
    expect(f.chain.links[2].evidence).toContain("reported 404");
    expect(f.chain.next).toMatch(/Fix it/);
  });

  it("offers the self-check with the method the route facts say reaches data unsigned", async () => {
    s.runs.mockResolvedValue([{ fullName: "acme/app", startedAt: "2026-09-30T00:00:00Z", status: "complete", stack: null, coverage: [],
      routeFacts: [{ path: "/api/orders/[id]", file: "app/api/orders/[id]/route.ts", tables: [], authenticated: false, ownershipFiltered: false,
        machineGated: false, methods: ["GET", "DELETE"], unrefusedMethods: ["DELETE"] }] }]);
    const open = (await (await get("?repository=acme/app")).json()).openFindings.find((f: { id: string }) => f.id === "agent:open");
    expect(open.selfCheck).toMatch(/^curl -i -X DELETE /);
  });

  it("does not serve an unselected repository and says unknown before any audit", async () => {
    expect((await get("?repository=someone/else")).status).toBe(404);
    s.runs.mockResolvedValue([]); s.source.mockResolvedValue({ repositoryId: "r1" });
    const body = await (await get("?repository=acme/app")).json();
    expect(body.lastAudit).toBeNull();
    expect(body.guardrails).toBeNull();
  });
});
