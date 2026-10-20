import { beforeEach, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import type { NextRequest } from "next/server";

// 2026-10-20: GitHub delivers a signed webhook about 3 s after every push to
// main, and ShipLock answered each with "ok" and did nothing, so a founder who
// pushes straight to the default branch was rechecked once a day at most. A
// push now queues the repository's source scan (secrets, dependencies,
// history), coalesced with the pull request path in the same 10-minute bucket.
const mocks = vi.hoisted(() => ({ audit: vi.fn(), job: vi.fn(), check: vi.fn(), intel: vi.fn(), worker: vi.fn(),
  profile: vi.fn(), repository: vi.fn(), rpc: vi.fn() }));
vi.mock("next/server", async (original) => ({ ...(await original<typeof import("next/server")>()), after: () => {} }));
vi.mock("@/lib/jobs/queue", () => ({ enqueueAuditJob: mocks.audit, enqueueJob: mocks.job,
  enqueuePullRequestCheck: mocks.check, enqueuePullRequestIntelligence: mocks.intel }));
vi.mock("@/lib/jobs/worker", () => ({ runNextJob: mocks.worker }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  rpc: mocks.rpc,
  from: (table: string) => {
    const q = { select: () => q, eq: () => q, maybeSingle: table === "repositories" ? mocks.repository : mocks.profile };
    return q;
  },
}) }));

const SECRET = "webhook-secret";
process.env.GITHUB_WEBHOOK_SECRET = SECRET;
const { POST } = await import("./route");

const sign = (raw: string) => `sha256=${crypto.createHmac("sha256", SECRET).update(raw).digest("hex")}`;
const req = (body: unknown, signature?: string) => {
  const raw = JSON.stringify(body);
  return new Request("https://x/api/monitor/github", { method: "POST",
    headers: { "x-hub-signature-256": signature ?? sign(raw), "x-github-event": "push", "content-type": "application/json" }, body: raw }) as unknown as NextRequest;
};
const pushed = (over: Record<string, unknown> = {}) => ({
  ref: "refs/heads/main", after: "f".repeat(40), deleted: false, installation: { id: 42 },
  repository: { full_name: "acme/app", default_branch: "main" }, ...over,
});
const owner = "22222222-2222-4222-8222-222222222222", repo = "33333333-3333-4333-8333-333333333333";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile.mockResolvedValue({ data: { id: owner, is_paid: true }, error: null });
  mocks.repository.mockResolvedValue({ data: { id: repo }, error: null });
  mocks.job.mockResolvedValue("job");
});

describe("recheck after a push to the default branch", () => {
  it("queues one source scan for the selected repository, in the pull request path's bucket", async () => {
    const now = vi.spyOn(Date, "now").mockReturnValue(1_800_000_000_000);
    try {
      expect((await POST(req(pushed()))).status).toBe(200);
    } finally { now.mockRestore(); }
    const bucket = Math.floor(1_800_000_000_000 / (10 * 60 * 1000));
    expect(mocks.job).toHaveBeenCalledWith(owner, repo, "source", `webhook-source:${repo}:${bucket}`);
    expect(mocks.audit).not.toHaveBeenCalled();
    expect(mocks.check).not.toHaveBeenCalled();
  });

  it("ignores another branch, a deleted branch, a malformed commit and a repository not selected", async () => {
    await POST(req(pushed({ ref: "refs/heads/feature" })));
    await POST(req(pushed({ deleted: true, after: "0".repeat(40) })));
    await POST(req(pushed({ after: "not-a-sha" })));
    mocks.repository.mockResolvedValueOnce({ data: null, error: null });
    await POST(req(pushed()));
    expect(mocks.job).not.toHaveBeenCalled();
  });

  it("refuses an unsigned delivery and asks GitHub to retry when admission fails", async () => {
    expect((await POST(req(pushed(), "sha256=" + "0".repeat(64)))).status).toBe(401);
    mocks.job.mockRejectedValueOnce(new Error("down"));
    expect((await POST(req(pushed()))).status).toBe(503);
  });
});
