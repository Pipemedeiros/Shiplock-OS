import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";

// secmax: proves the paywall actually blocks execution, not just the
// response shape — every negative test here asserts scanProject was never
// even called, so a bypass can't slip through by e.g. returning 402 while
// still running (and billing) the scan.
const scanProjectMock = vi.fn();
const analyzeResultMock = vi.fn();
const runExposedPathScanMock = vi.fn();
const getUserMock = vi.fn();
const singleMock = vi.fn();
const encryptMock = vi.fn();
const profileEqMock = vi.fn();
const profileUpdateMock = vi.fn();
const recheckMock = vi.fn();

vi.mock("@/lib/scanner", () => ({
  scanProject: scanProjectMock,
  ScanError: class ScanError extends Error {
    statusCode?: number;
  },
}));
vi.mock("@/lib/security/exposedPathsRun", () => ({ runExposedPathScan: runExposedPathScanMock }));
vi.mock("@/lib/jobs/manualRecheck", () => ({ queueCustomerRecheck: recheckMock }));
vi.mock("@/lib/analyzer", () => ({ analyzeResult: analyzeResultMock }));
vi.mock("@/lib/rateLimit", () => ({ getClientIpHash: () => "iphash" }));
vi.mock("@/lib/crypto", () => ({ encrypt: encryptMock }));
vi.mock("@/lib/monitoring/findings", () => ({ extractFindings: () => [] }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    auth: { getUser: getUserMock },
    from: (table: string) => ({
      select: () => ({
        eq: (col: string, val: string) => {
          if (table === "user_profiles") profileEqMock(col, val);
          return { single: singleMock, maybeSingle: singleMock };
        },
      }),
      update: (payload: unknown) => { profileUpdateMock(payload); return { eq: () => Promise.resolve({ error: null }) }; },
      insert: () => Promise.resolve({ error: null }),
    }),
  }),
}));

const { POST } = await import("./route");

const VALID_BODY = { supabaseUrl: "https://myproj.supabase.co", anonKey: "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.sig" };

function req(body: unknown, headers: Record<string, string> = {}) {
  return new NextRequest("https://shiplock.dev/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

describe("POST /api/scan — auth & paywall are enforced, not just labeled", () => {
  beforeEach(() => {
    scanProjectMock.mockReset();
    analyzeResultMock.mockReset();
    runExposedPathScanMock.mockReset();
    getUserMock.mockReset();
    singleMock.mockReset();
    encryptMock.mockReset();
    profileEqMock.mockReset();
    profileUpdateMock.mockReset();
    recheckMock.mockReset().mockResolvedValue("job-1");
  });

  it("401s with no Authorization header and never runs the scan", async () => {
    const res = await POST(req(VALID_BODY));
    expect(res.status).toBe(401);
    expect(scanProjectMock).not.toHaveBeenCalled();
  });

  it("401s on a garbage/forged bearer token and never runs the scan", async () => {
    getUserMock.mockResolvedValue({ data: { user: null } });
    const res = await POST(req(VALID_BODY, { authorization: "Bearer forged.token.value" }));
    expect(res.status).toBe(401);
    expect(scanProjectMock).not.toHaveBeenCalled();
  });

  it("refuses a caller with no profile row, and a client-claimed paid flag grants nothing", async () => {
    // Billing is parked (lib/access.ts), so is_paid: false no longer 402s. What
    // must still hold is that access is decided from the database record and
    // never from the body: a caller the database does not know is refused, and
    // a smuggled isPaid does not conjure the record into existence.
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({ data: null });

    const res = await POST(
      req({ ...VALID_BODY, isPaid: true, is_paid: true }, { authorization: "Bearer real-token" })
    );

    expect(res.status).toBe(402);
    expect(scanProjectMock).not.toHaveBeenCalled();
  });

  it("lets an authenticated account through while billing is parked", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({ data: { is_paid: false, monitored_project_url: null } });

    // The assertion is that the ACCESS GATE let it through — the scan itself is
    // allowed to fall over on unmocked collaborators further down the route.
    await POST(req(VALID_BODY, { authorization: "Bearer real-token" })).catch(() => undefined);

    expect(scanProjectMock).toHaveBeenCalled();
  });

  it("IDOR: the profile lookup is keyed off the token-resolved id, never a client-supplied one", async () => {
    // admin.auth.getUser is the only source of userId — there is no userId
    // field read from the body at all, but this proves it even if an
    // attacker tries to smuggle one in.
    getUserMock.mockResolvedValue({ data: { user: { id: "victim-id" } } });
    singleMock.mockResolvedValue({ data: { is_paid: true, monitored_project_url: null } });
    scanProjectMock.mockResolvedValue({ keyAnalysis: { isServiceRole: false }, appUrlChecked: false });
    analyzeResultMock.mockResolvedValue({ summary: "ok", issues: [] });

    await POST(req({ ...VALID_BODY, userId: "attacker-supplied-id" }, { authorization: "Bearer valid" }));

    expect(profileEqMock).toHaveBeenCalledWith("id", "victim-id");
    expect(profileEqMock).not.toHaveBeenCalledWith("id", "attacker-supplied-id");
  });

  it("400s on malformed JSON without leaking a stack trace", async () => {
    const badReq = new NextRequest("https://shiplock.dev/api/scan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not valid json",
    });
    const res = await POST(badReq);
    const body = await res.json();
    expect(res.status).toBe(400);
    expect(JSON.stringify(body)).not.toMatch(/at .*\.ts:\d+/); // no stack frame leaked
  });

  it("rejects a service-role key submission instead of persisting it for monitoring", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({ data: { is_paid: true, monitored_project_url: null } });
    // A service-role key masquerading as an anon key — scanner would flag it
    // CRITICAL; the route must still refuse to store it for later monitoring.
    scanProjectMock.mockResolvedValue({
      keyAnalysis: { isServiceRole: true },
      appUrlChecked: false,
    });
    analyzeResultMock.mockResolvedValue({ summary: "ok", issues: [{ severity: "CRITICAL" }] });

    const res = await POST(req(VALID_BODY, { authorization: "Bearer valid" }));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.monitoringEnrolled).toBe(false);
    expect(encryptMock).not.toHaveBeenCalled();
  });

  it("type-confusion: a stringly-typed replaceProject('true') does not bypass the one-project-per-subscription gate", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({
      data: { is_paid: true, monitored_project_url: "https://other-project.supabase.co" },
    });

    const res = await POST(
      req({ ...VALID_BODY, replaceProject: "true" }, { authorization: "Bearer valid" })
    );

    // Only a strict boolean `true` should authorize the switch — a truthy
    // string must still hit the 409 project-limit guard.
    expect(res.status).toBe(409);
    expect(scanProjectMock).not.toHaveBeenCalled();
  });

  it("mints a new endpoint connection epoch whenever monitoring credentials are stored (2D)", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({ data: { is_paid: true, monitored_project_url: null } });
    scanProjectMock.mockResolvedValue({ keyAnalysis: { isServiceRole: false }, appUrlChecked: false });
    analyzeResultMock.mockResolvedValue({ summary: "ok", issues: [] });
    encryptMock.mockReturnValue("encrypted-anon");
    await POST(req(VALID_BODY, { authorization: "Bearer valid" }));
    expect(profileUpdateMock).toHaveBeenCalledWith(expect.objectContaining({
      monitored_anon_key_encrypted: "encrypted-anon",
      supabase_endpoint_connection_epoch: expect.stringMatching(/^[a-f0-9]{64}$/),
    }));
  });

  it("queues the app-surface follow-up instead of probing inside the request (3F-C2c-5)", async () => {
    getUserMock.mockResolvedValue({ data: { user: { id: "u1" } } });
    singleMock.mockResolvedValue({ data: { is_paid: true, monitored_project_url: null } });
    scanProjectMock.mockResolvedValue({ keyAnalysis: { isServiceRole: false }, appUrlChecked: true });
    analyzeResultMock.mockResolvedValue({ summary: "ok", issues: [] });
    encryptMock.mockReturnValue("encrypted-anon");
    await POST(req({ ...VALID_BODY, appUrl: "https://app.example.com" }, { authorization: "Bearer valid" }));
    expect(recheckMock).toHaveBeenCalledWith("u1", "app-surface");
    expect(runExposedPathScanMock).not.toHaveBeenCalled();
  });
});
