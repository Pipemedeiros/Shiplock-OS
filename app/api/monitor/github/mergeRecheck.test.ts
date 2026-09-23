import { beforeEach, describe, expect, it, vi } from "vitest";
import crypto from "node:crypto";
import type { NextRequest } from "next/server";

// 8-R: a human merge on the default branch queues a recheck of that branch and
// stamps ShipLock's receipt for the merged PR. Nothing else acts on "closed".
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
const req = (body: unknown) => {
  const raw = JSON.stringify(body);
  return new Request("https://x/api/monitor/github", { method: "POST",
    headers: { "x-hub-signature-256": sign(raw), "x-github-event": "pull_request", "content-type": "application/json" }, body: raw }) as unknown as NextRequest;
};
const merged = (over: Record<string, unknown> = {}) => ({
  action: "closed", installation: { id: 42 }, number: 7,
  repository: { full_name: "acme/app", default_branch: "main" },
  pull_request: { number: 7, merged: true, merge_commit_sha: "e".repeat(40), base: { ref: "main" }, head: { sha: "a".repeat(40) } },
  ...over,
});
const owner = "22222222-2222-4222-8222-222222222222", repo = "33333333-3333-4333-8333-333333333333";

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile.mockResolvedValue({ data: { id: owner, is_paid: true }, error: null });
  mocks.repository.mockResolvedValue({ data: { id: repo, last_source_scan_at: null }, error: null });
  mocks.audit.mockResolvedValue({ job_id: "j", run_id: "r" });
  mocks.rpc.mockResolvedValue({ data: 1, error: null });
});

describe("recheck after a human merge (8-R)", () => {
  it("queues one recheck of the default branch at the merge commit and stamps the receipt", async () => {
    expect((await POST(req(merged()))).status).toBe(200);
    expect(mocks.audit).toHaveBeenCalledWith(owner, repo, `merge:acme/app:${"e".repeat(40)}`, "pull_request");
    expect(mocks.rpc).toHaveBeenCalledWith("record_repair_merge", { p_user: owner, p_repository: repo, p_pr: 7 });
    expect(mocks.check).not.toHaveBeenCalled();
  });

  it("ignores a PR closed without merging, and a merge into another branch", async () => {
    await POST(req(merged({ pull_request: { number: 7, merged: false, base: { ref: "main" }, head: { sha: "a".repeat(40) } } })));
    await POST(req(merged({ pull_request: { number: 7, merged: true, merge_commit_sha: "e".repeat(40), base: { ref: "feature" }, head: { sha: "a".repeat(40) } } })));
    expect(mocks.audit).not.toHaveBeenCalled();
    expect(mocks.rpc).not.toHaveBeenCalled();
  });

  it("does nothing for a repository that is not selected", async () => {
    mocks.repository.mockResolvedValue({ data: null, error: null });
    expect((await POST(req(merged()))).status).toBe(200);
    expect(mocks.audit).not.toHaveBeenCalled();
  });

  it("asks GitHub to redeliver when admission or the stamp fails", async () => {
    mocks.audit.mockRejectedValueOnce(new Error("down"));
    expect((await POST(req(merged()))).status).toBe(503);
    mocks.rpc.mockResolvedValueOnce({ data: null, error: { message: "down" } });
    expect((await POST(req(merged()))).status).toBe(503);
  });
});
