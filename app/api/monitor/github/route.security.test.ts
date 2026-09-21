import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHmac } from "crypto";
import { NextRequest } from "next/server";

const runGithubScanMock = vi.fn();
const enqueueAuditJobMock = vi.fn();
const runNextAuditJobMock = vi.fn();
const maybeSingleMock = vi.fn();
const updateEqMock = vi.fn();

// `after()` defers work until the response is sent, which is the whole point:
// GitHub allows a webhook ten seconds and a real scan takes longer. Nothing
// runs it in a test, so it is executed inline here. What is being asserted is
// still the same thing, that the work is dispatched and with what.
const afterWork: Promise<unknown>[] = [];
/** Wait for work `after()` deferred, which a test environment never runs. */
const flushAfter = () => Promise.allSettled(afterWork.splice(0));

vi.mock("next/server", async () => {
  const actual = await vi.importActual<typeof import("next/server")>("next/server");
  return {
    ...actual,
    after: (fn: () => unknown) => {
      afterWork.push(Promise.resolve().then(fn));
    },
  };
});

vi.mock("@/lib/deep/githubRun", () => ({ runGithubScan: runGithubScanMock }));
vi.mock("@/lib/jobs/queue", () => ({ enqueueAuditJob: enqueueAuditJobMock }));
vi.mock("@/lib/jobs/auditWorker", () => ({ runNextAuditJob: runNextAuditJobMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({ eq: () => ({ maybeSingle: maybeSingleMock }) }),
      update: (patch: unknown) => ({ eq: (...args: unknown[]) => { updateEqMock(patch, ...args); return Promise.resolve({ error: null }); } }),
    }),
  }),
}));

const { POST } = await import("./route");

const SECRET = "test-webhook-secret";

function sign(raw: string): string {
  return "sha256=" + createHmac("sha256", SECRET).update(raw).digest("hex");
}

function req(rawBody: string, sig: string | null, event = "pull_request") {
  const headers: Record<string, string> = { "x-github-event": event };
  if (sig !== null) headers["x-hub-signature-256"] = sig;
  return new NextRequest("https://shiplock.dev/api/monitor/github", {
    method: "POST",
    headers,
    body: rawBody,
  });
}

describe("POST /api/monitor/github — HMAC-forged webhook payloads must not trigger a scan", () => {
  const prevSecret = process.env.GITHUB_WEBHOOK_SECRET;

  beforeEach(() => {
    process.env.GITHUB_WEBHOOK_SECRET = SECRET;
    afterWork.splice(0);
    runGithubScanMock.mockReset();
    enqueueAuditJobMock.mockReset();
    runNextAuditJobMock.mockReset();
    maybeSingleMock.mockReset();
    updateEqMock.mockReset();
  });

  afterEach(() => {
    process.env.GITHUB_WEBHOOK_SECRET = prevSecret;
  });

  it("401s a payload with no signature header at all", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 1 } });
    const res = await POST(req(raw, null));
    expect(res.status).toBe(401);
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("401s a FORGED signature — proves an attacker can't trigger a rescan (or DoS the scan budget) for someone else's installation", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 1 } });
    const res = await POST(req(raw, "sha256=" + "0".repeat(64)));
    expect(res.status).toBe(401);
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("401s when the signature was computed over a DIFFERENT body than the one delivered (tamper-after-sign)", async () => {
    const signedBody = JSON.stringify({ action: "opened", installation: { id: 1 } });
    const sig = sign(signedBody);
    const tamperedBody = JSON.stringify({ action: "opened", installation: { id: 999 } });
    const res = await POST(req(tamperedBody, sig));
    expect(res.status).toBe(401);
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("accepts a correctly signed payload and scans only the mapped, paid installation owner", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    maybeSingleMock.mockResolvedValue({ data: { id: "owner-1", is_paid: true, last_source_scan_at: null } });
    runGithubScanMock.mockResolvedValue(undefined);

    const res = await POST(req(raw, sign(raw)));
    await flushAfter();
    expect(res.status).toBe(200);
    expect(runGithubScanMock).toHaveBeenCalledWith("owner-1", 42);
  });

  it("never scans for an installation with no matching account, even with a validly signed payload", async () => {
    // A valid signature proves the payload came from GitHub. It does not prove
    // the installation belongs to anyone here — an install on a repo we have no
    // account for must not start work. Billing being parked does not change it.
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    maybeSingleMock.mockResolvedValue({ data: null });

    await POST(req(raw, sign(raw)));
    await flushAfter();
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("is inert (200, no processing) when the secret isn't configured, rather than accepting anything as valid", async () => {
    delete process.env.GITHUB_WEBHOOK_SECRET;
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    const res = await POST(req(raw, "sha256=anything"));
    expect(res.status).toBe(200);
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });
});
