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
const runRepositoryAuditMock = vi.fn();
const maybeSingleMock = vi.fn();

vi.mock("@/lib/agent/prCheck", () => ({ runPullRequestCheck: runPullRequestCheckMock }));
vi.mock("@/lib/deep/githubRun", () => ({ runGithubScan: runGithubScanMock }));
vi.mock("@/lib/agent/audit", () => ({ runRepositoryAudit: runRepositoryAuditMock }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          maybeSingle: maybeSingleMock,
          eq: () => ({ then: (r: (v: unknown) => unknown) => r({ data: [] }) }),
        }),
      }),
      update: () => ({ eq: () => ({ then: (r: (v: unknown) => unknown) => r({ error: null }) }) }),
    }),
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
    // Inside the coalescing window: a full re-scan was done seconds ago.
    maybeSingleMock.mockResolvedValue({
      data: { id: "u1", is_paid: true, last_source_scan_at: new Date().toISOString() },
    });
  });

  it("still posts the check when the full re-scan is coalesced away", async () => {
    await POST(req(payload));

    expect(runPullRequestCheckMock).toHaveBeenCalledWith(
      expect.objectContaining({ fullName: "acme/app", prNumber: 7, headSha: "abc123" }),
    );
    // The expensive pass is the one that gets skipped.
    expect(runGithubScanMock).not.toHaveBeenCalled();
  });

  it("does not let a failing check stop the rest of the pass", async () => {
    maybeSingleMock.mockResolvedValue({ data: { id: "u1", is_paid: true, last_source_scan_at: null } });
    runPullRequestCheckMock.mockRejectedValue(new Error("GitHub 503"));

    const res = await POST(req(payload));

    // 200 regardless, or GitHub retries the delivery and we do the work twice.
    expect(res.status).toBe(200);
    expect(runGithubScanMock).toHaveBeenCalled();
  });

  it("posts no check for an event with no pull request attached", async () => {
    const raw = JSON.stringify({ action: "opened", installation: { id: 42 } });
    await POST(req(raw));
    expect(runPullRequestCheckMock).not.toHaveBeenCalled();
  });
});
