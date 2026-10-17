import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

// The customer's agent runs the one harmless self-check ShipLock offers and
// reports the status. ShipLock derives the request itself, refuses the
// founder's production address, and stores only what the agent says it saw.
const s = vi.hoisted(() => ({ auth: vi.fn(), findings: vi.fn(), runs: vi.fn(), rpc: vi.fn(), profile: { monitored_app_url: "https://app.acme.com" } as Record<string, unknown> }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: s.auth }));
vi.mock("@/lib/agent/dashboardData", () => ({ getOpenFindings: s.findings, getRuns: s.runs }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  rpc: s.rpc,
  from: () => { const q = { select: () => q, eq: () => q, maybeSingle: async () => ({ data: s.profile, error: null }) }; return q; },
}) }));
const { POST } = await import("./route");

const post = (body: unknown) => POST(new NextRequest("https://shiplock.dev/api/mcp/self-check", {
  method: "POST", headers: { authorization: "Bearer t", "content-type": "application/json" }, body: JSON.stringify(body) }));
const open = { rowId: "11111111-1111-4111-8111-111111111111", id: "agent:notes", repository: "acme/app", entry: "/api/notes/[id]", attackClass: "missing_authentication" };

beforeEach(() => {
  s.auth.mockReset().mockResolvedValue({ userId: "u1" });
  s.findings.mockReset().mockResolvedValue([open]);
  s.rpc.mockReset().mockResolvedValue({ error: null });
  s.runs.mockReset().mockResolvedValue([]);
  s.profile = { monitored_app_url: "https://app.acme.com" };
});

describe("POST /api/mcp/self-check", () => {
  it("records ShipLock's own request with the agent's status and host, and says what it means", async () => {
    const res = await post({ findingId: "agent:notes", status: 404, host: "http://localhost:3000/ignored?x=1", method: "DELETE", path: "/admin" });
    expect(res.status).toBe(200);
    expect(s.rpc).toHaveBeenCalledWith("record_self_check", { p_user: "u1", p_finding_row: open.rowId, p_method: "GET",
      p_path: "/api/notes/00000000-0000-4000-8000-000000000000", p_status: 404, p_host: "localhost:3000" });
    const body = await res.json();
    expect(body).toMatchObject({ recorded: true, outcome: "reached" });
    expect(body.next).toMatch(/not proof/);
  });

  it("records the method the audit's route facts give, the same one get_security_context offered", async () => {
    s.runs.mockResolvedValue([{ fullName: "acme/app", routeFacts: [{ path: "/api/notes/[id]", methods: ["GET", "DELETE"], unrefusedMethods: ["DELETE"] }] },
      { fullName: "acme/app", routeFacts: [{ path: "/api/notes/[id]", methods: ["GET"] }] }]);
    expect((await post({ findingId: "agent:notes", status: 404, host: "localhost:3000" })).status).toBe(200);
    expect(s.rpc.mock.calls[0][1].p_method).toBe("DELETE");
  });

  it("refuses the founder's production address before writing", async () => {
    const res = await post({ findingId: "agent:notes", status: 200, host: "https://APP.acme.com" });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/never production/);
    expect(s.rpc).not.toHaveBeenCalled();
  });

  it.each([
    [{ findingId: "agent:notes", status: 99, host: "localhost" }],
    [{ findingId: "agent:notes", status: 200, host: "user:pw@localhost" }],
    [{ findingId: "agent:notes", status: 200, host: "bad host" }],
    [{ findingId: "agent:notes", status: "200", host: "localhost" }],
  ])("refuses a malformed report %#", async (body) => {
    expect((await post(body)).status).toBe(400);
    expect(s.rpc).not.toHaveBeenCalled();
  });

  it("refuses an unknown finding, one with no self-check, and an ambiguous id", async () => {
    expect((await post({ findingId: "agent:nope", status: 200, host: "localhost" })).status).toBe(404);
    s.findings.mockResolvedValue([{ ...open, attackClass: "missing_ownership" }]);
    expect((await post({ findingId: "agent:notes", status: 200, host: "localhost" })).status).toBe(409);
    s.findings.mockResolvedValue([open, { ...open, rowId: "22222222-2222-4222-8222-222222222222", repository: "acme/web" }]);
    expect((await post({ findingId: "agent:notes", status: 200, host: "localhost" })).status).toBe(409);
    expect((await post({ findingId: "agent:notes", repository: "acme/web", status: 200, host: "localhost" })).status).toBe(200);
    expect(s.rpc).toHaveBeenCalledTimes(1);
    expect(s.rpc.mock.calls[0][1].p_finding_row).toBe("22222222-2222-4222-8222-222222222222");
  });

  it("answers an unauthenticated agent with the token error and writes nothing", async () => {
    s.auth.mockResolvedValue({ error: new Response(JSON.stringify({ error: "token" }), { status: 401 }) });
    expect((await post({ findingId: "agent:notes", status: 200, host: "localhost" })).status).toBe(401);
    expect(s.rpc).not.toHaveBeenCalled();
  });

  it("says unavailable when the write fails, never recorded", async () => {
    s.rpc.mockResolvedValue({ error: { message: "finding unavailable" } });
    expect((await post({ findingId: "agent:notes", status: 200, host: "localhost" })).status).toBe(503);
  });
});
