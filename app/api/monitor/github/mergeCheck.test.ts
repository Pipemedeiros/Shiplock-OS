import { describe, expect, it, vi, beforeEach } from "vitest";
import crypto from "node:crypto";

// The merge check must survive the coalescing window. `synchronize` fires on
// every push to an open pull request, and the window exists to stop the full
// repository re-scan running twenty times. The CHECK is a different thing: it
// is the answer the developer is waiting on, and coalescing it would mean the
// second push to a branch silently inherits the first push's verdict — a green
// check on code nobody looked at.

const enqueueAuditJobMock = vi.fn();
const enqueueJobMock = vi.fn();
const enqueuePullRequestCheckMock = vi.fn();
const enqueuePullRequestIntelligenceMock = vi.fn();
const runNextJobMock = vi.fn();
const profileMaybeSingleMock = vi.fn();
const repositoryMaybeSingleMock = vi.fn();

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

vi.mock("@/lib/jobs/queue", () => ({
  enqueueAuditJob: enqueueAuditJobMock,
  enqueueJob: enqueueJobMock,
  enqueuePullRequestCheck: enqueuePullRequestCheckMock,
  enqueuePullRequestIntelligence: enqueuePullRequestIntelligenceMock,
}));
vi.mock("@/lib/jobs/worker", () => ({ runNextJob: runNextJobMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      const query = {
        eq: () => query,
        maybeSingle: table === "repositories" ? repositoryMaybeSingleMock : profileMaybeSingleMock,
      };
      return {
        select: () => query,
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
  pull_request: { number: 7, head: { sha: "abc1234" } },
});

describe("the merge check and the coalescing window", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    afterWork.splice(0);
    // Inside the coalescing window: a full re-scan was done seconds ago.
    profileMaybeSingleMock.mockResolvedValue({
      data: { id: "22222222-2222-4222-8222-222222222222", is_paid: true },
      error: null,
    });
    repositoryMaybeSingleMock.mockResolvedValue({
      data: {
        id: "33333333-3333-4333-8333-333333333333",
        last_source_scan_at: new Date().toISOString(),
      },
      error: null,
    });
    enqueueAuditJobMock.mockResolvedValue({
      job_id: "44444444-4444-4444-8444-444444444444",
      run_id: "55555555-5555-4555-8555-555555555555",
    });
    enqueuePullRequestCheckMock.mockResolvedValue("66666666-6666-4666-8666-666666666666");
    enqueueJobMock.mockResolvedValue("77777777-7777-4777-8777-777777777777");
    runNextJobMock.mockResolvedValue(true);
  });

  it("still durably queues the check when the full re-scan is coalesced away", async () => {
    await POST(req(payload));
    await flushAfter();

    expect(enqueuePullRequestCheckMock).toHaveBeenCalledWith(
      "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333",
      "pr-check:acme/app:7:abc1234", 7, "abc1234",
    );
    // The expensive pass is the one that gets skipped.
    expect(enqueueJobMock).not.toHaveBeenCalled();
    expect(enqueueAuditJobMock).not.toHaveBeenCalled();
  });

  it("durably admits source work before waking the worker", async () => {
    repositoryMaybeSingleMock.mockResolvedValue({
      data: { id: "33333333-3333-4333-8333-333333333333", last_source_scan_at: null },
      error: null,
    });
    const res = await POST(req(payload));
    await flushAfter();
    await flushAfter();

    expect(res.status).toBe(200);
    expect(enqueueJobMock).toHaveBeenCalledWith(
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
      "source",
      expect.stringMatching(/^webhook-source:33333333-3333-4333-8333-333333333333:/),
    );
    expect(runNextJobMock).toHaveBeenCalledOnce();
  });

  it("durably admits only the event repository with a repository and head-SHA key", async () => {
    const opened = payload.replace('"synchronize"', '"opened"');

    const res = await POST(req(opened));
    expect(res.status).toBe(200);
    expect(enqueueAuditJobMock).toHaveBeenCalledWith(
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
      "pull-request:acme/app:abc1234",
      "pull_request",
    );
    await flushAfter();
    expect(runNextJobMock).toHaveBeenCalledOnce();
  });

  it("returns a retryable response before scheduling side effects when admission fails", async () => {
    enqueueAuditJobMock.mockRejectedValue(new Error("private database detail"));
    const opened = payload.replace('"synchronize"', '"opened"');

    const res = await POST(req(opened));
    expect(res.status).toBe(503);
    expect(afterWork).toHaveLength(0);
    expect(enqueuePullRequestCheckMock).not.toHaveBeenCalled();
    expect(enqueueJobMock).not.toHaveBeenCalled();
    expect(runNextJobMock).not.toHaveBeenCalled();
  });

  it("returns a retryable response when durable check admission fails", async () => {
    enqueuePullRequestCheckMock.mockRejectedValue(new Error("private database detail"));
    const res = await POST(req(payload));
    expect(res.status).toBe(503);
    expect(afterWork).toHaveLength(0);
    expect(enqueueJobMock).not.toHaveBeenCalled();
    expect(runNextJobMock).not.toHaveBeenCalled();
  });

  it("returns a retryable response when durable source admission fails", async () => {
    enqueueJobMock.mockRejectedValue(new Error("private database detail"));

    const res = await POST(req(payload.replace('"synchronize"', '"opened"')));
    expect(res.status).toBe(503);
    expect(afterWork).toHaveLength(0);
    expect(runNextJobMock).not.toHaveBeenCalled();
  });

  it("does not write a check or audit for an installation repository the customer did not select", async () => {
    repositoryMaybeSingleMock.mockResolvedValue({ data: null, error: null });

    const res = await POST(req(payload));
    await flushAfter();
    expect(res.status).toBe(200);
    expect(enqueueAuditJobMock).not.toHaveBeenCalled();
    expect(enqueuePullRequestCheckMock).not.toHaveBeenCalled();
    expect(enqueueJobMock).not.toHaveBeenCalled();
  });

  it("posts no check for an event with no pull request attached", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    await POST(req(raw));
    await flushAfter();
    expect(enqueuePullRequestCheckMock).not.toHaveBeenCalled();
  });

  it("admits an every-PR intelligence scan with the check, only at a full head sha (10B-2c)", async () => {
    await POST(req(payload));
    expect(enqueuePullRequestIntelligenceMock).not.toHaveBeenCalled();
    const full = "d".repeat(40);
    const raw = JSON.stringify({ ...JSON.parse(payload), pull_request: { number: 7, head: { sha: full } } });
    enqueuePullRequestIntelligenceMock.mockResolvedValue(null);
    expect((await POST(req(raw))).status).toBe(200);
    expect(enqueuePullRequestIntelligenceMock).toHaveBeenCalledWith(
      "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", 7, full);
    enqueuePullRequestIntelligenceMock.mockRejectedValue(new Error("down"));
    expect((await POST(req(raw))).status).toBe(503);
  });
});
