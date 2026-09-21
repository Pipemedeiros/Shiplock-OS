import { describe, expect, it, vi, beforeEach } from "vitest";
import crypto from "node:crypto";

// The merge check must survive the coalescing window. `synchronize` fires on
// every push to an open pull request, and the window exists to stop the full
// repository re-scan running twenty times. The CHECK is a different thing: it
// is the answer the developer is waiting on, and coalescing it would mean the
// second push to a branch silently inherits the first push's verdict — a green
// check on code nobody looked at.

const runPullRequestCheckMock = vi.fn();
const runGithubScanMock = vi.fn();
const enqueueAuditJobMock = vi.fn();
const runNextAuditJobMock = vi.fn();
const profileMaybeSingleMock = vi.fn();
const repositoryMaybeSingleMock = vi.fn();
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

vi.mock("@/lib/agent/prCheck", () => ({ runPullRequestCheck: runPullRequestCheckMock }));
vi.mock("@/lib/deep/githubRun", () => ({ runGithubScan: runGithubScanMock }));
vi.mock("@/lib/jobs/queue", () => ({ enqueueAuditJob: enqueueAuditJobMock }));
vi.mock("@/lib/jobs/auditWorker", () => ({ runNextAuditJob: runNextAuditJobMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      const query = {
        eq: () => query,
        maybeSingle: table === "repositories" ? repositoryMaybeSingleMock : profileMaybeSingleMock,
      };
      return {
        select: () => query,
        update: (patch: unknown) => ({
          eq: (...args: unknown[]) => {
            updateEqMock(patch, ...args);
            return Promise.resolve({ error: null });
          },
        }),
      };
    },
  }),
}));

const SECRET = "webhook-secret";
process.env.GITHUB_WEBHOOK_SECRET = SECRET;

const { POST } = await import("./route");

const sign = (raw: string) =>
  `sha256=${crypto.createHmac("sha256", SECRET).update(raw).digest("hex")}`;

import type { NextRequest } from "next/server";

function req(raw: string) {
  return new Request("https://x/api/monitor/github", {
    method: "POST",
    headers: {
      "x-hub-signature-256": sign(raw),
      "x-github-event": "pull_request",
      "content-type": "application/json",
    },
    body: raw,
  }) as unknown as NextRequest;
}

const payload = JSON.stringify({
  action: "synchronize",
  installation: { id: 42 },
  repository: { full_name: "acme/app" },
  pull_request: { number: 7, head: { sha: "abc123" } },
});

describe("the merge check and the coalescing window", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    afterWork.splice(0);
    // Inside the coalescing window: a full re-scan was done seconds ago.
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true, last_source_scan_at: new Date().toISOString() },
      error: null,
    });
    repositoryMaybeSingleMock.mockResolvedValue({
      data: { id: "33333333-3333-4333-8333-333333333333" },
      error: null,
    });
    enqueueAuditJobMock.mockResolvedValue({
      job_id: "44444444-4444-4444-8444-444444444444",
      run_id: "55555555-5555-4555-8555-555555555555",
    });
    runNextAuditJobMock.mockResolvedValue(true);
    runGithubScanMock.mockResolvedValue(undefined);
  });

  it("still posts the check when the full re-scan is coalesced away", async () => {
    await POST(req(payload));
    await flushAfter();

    expect(runPullRequestCheckMock).toHaveBeenCalledWith(
      expect.objectContaining({ fullName: "acme/app", prNumber: 7, headSha: "abc123" }),
    );
    // The expensive pass is the one that gets skipped.
    expect(runGithubScanMock).not.toHaveBeenCalled();
    expect(enqueueAuditJobMock).not.toHaveBeenCalled();
  });

  it("does not let a failing check stop the rest of the pass", async () => {
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true, last_source_scan_at: null },
      error: null,
    });
    runPullRequestCheckMock.mockRejectedValue(new Error("GitHub 503"));

    const res = await POST(req(payload));
    await flushAfter();
    await flushAfter();

    // 200 regardless, or GitHub retries the delivery and we do the work twice.
    expect(res.status).toBe(200);
    expect(runGithubScanMock).toHaveBeenCalled();
    expect(runNextAuditJobMock).toHaveBeenCalledOnce();
  });

  it("durably admits only the event repository with a repository and head-SHA key", async () => {
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true, last_source_scan_at: null },
      error: null,
    });
    const opened = payload.replace('"synchronize"', '"opened"');

    const res = await POST(req(opened));
    expect(res.status).toBe(200);
    expect(enqueueAuditJobMock).toHaveBeenCalledWith(
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
      "pull-request:acme/app:abc123",
      "pull_request",
    );
    await flushAfter();
    expect(runNextAuditJobMock).toHaveBeenCalledOnce();
  });

  it("returns a retryable response before scheduling side effects when admission fails", async () => {
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true, last_source_scan_at: null },
      error: null,
    });
    enqueueAuditJobMock.mockRejectedValue(new Error("private database detail"));
    const opened = payload.replace('"synchronize"', '"opened"');

    const res = await POST(req(opened));
    expect(res.status).toBe(503);
    expect(afterWork).toHaveLength(0);
    expect(runPullRequestCheckMock).not.toHaveBeenCalled();
    expect(runGithubScanMock).not.toHaveBeenCalled();
    expect(runNextAuditJobMock).not.toHaveBeenCalled();
  });

  it("does not write a check or audit for an installation repository the customer did not select", async () => {
    repositoryMaybeSingleMock.mockResolvedValue({ data: null, error: null });

    const res = await POST(req(payload));
    await flushAfter();
    expect(res.status).toBe(200);
    expect(enqueueAuditJobMock).not.toHaveBeenCalled();
    expect(runPullRequestCheckMock).not.toHaveBeenCalled();
  });

  it("stamps source freshness only after a successful refresh", async () => {
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true, last_source_scan_at: null },
      error: null,
    });
    runGithubScanMock.mockRejectedValue(new Error("temporary GitHub failure"));

    const res = await POST(req(payload));
    await flushAfter();
    expect(res.status).toBe(200);
    expect(updateEqMock).not.toHaveBeenCalled();
  });

  it("posts no check for an event with no pull request attached", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    await POST(req(raw));
    await flushAfter();
    expect(runPullRequestCheckMock).not.toHaveBeenCalled();
  });
});
