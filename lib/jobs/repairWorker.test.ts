import { beforeEach, describe, expect, it, vi } from "vitest";

// 3F-C2d-2: a clicked repair opens its PR in the worker, under the job lease,
// and every outcome lands on the customer's receipt.
const mocks = vi.hoisted(() => ({ receipt: vi.fn(), rpc: vi.fn(), risk: vi.fn(), finding: vi.fn(), heartbeat: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({
  rpc: mocks.rpc,
  from: () => ({ select: () => ({ eq: () => ({ maybeSingle: mocks.receipt }) }) }),
}) }));
vi.mock("@/lib/fixes/riskFixPr", () => ({ openRiskFixPr: mocks.risk }));
vi.mock("@/lib/fixes/findingFixPr", () => ({ openFindingFixPr: mocks.finding }));
vi.mock("./queue", async (original) => ({
  ...await original<typeof import("./queue")>(),
  withLeaseHeartbeat: (_job: unknown, work: () => Promise<unknown>) => { mocks.heartbeat(); return work(); },
}));

import { executeRepairJob } from "./repairWorker";
import { PermanentJobError, type ClaimedJob } from "./queue";

const job: ClaimedJob = {
  id: "11111111-1111-4111-8111-111111111111", user_id: "22222222-2222-4222-8222-222222222222",
  repository_id: "33333333-3333-4333-8333-333333333333", audit_run_id: null,
  deduplication_key: "repair:click-1", kind: "repair", status: "running", attempts: 1,
  lease_token: "44444444-4444-4444-8444-444444444444", lease_until: "2099-01-01T00:00:00Z", checkpoint: 0,
};
const receipt = (over: Record<string, unknown> = {}) => ({ data: {
  user_id: job.user_id, repository_id: job.repository_id, action: "risk-fix-pr",
  finding_id: "agent:orders-idor", edited_content: null, status: "queued", ...over,
}, error: null });
const completed = () => mocks.rpc.mock.calls.filter(([name]) => name === "complete_repair_action").map(([, args]) => args);

beforeEach(() => {
  vi.clearAllMocks();
  mocks.receipt.mockResolvedValue(receipt());
  mocks.rpc.mockResolvedValue({ data: true, error: null });
  mocks.risk.mockResolvedValue({ status: "opened", url: "https://github.com/acme/app/pull/9", number: 9 });
  mocks.finding.mockResolvedValue({ status: "opened", url: "https://github.com/acme/app/pull/10", number: 10 });
});

describe("executeRepairJob", () => {
  it("opens a Risks-board fix PR under the lease and records it on the receipt", async () => {
    await executeRepairJob(job);
    expect(mocks.heartbeat).toHaveBeenCalled();
    expect(mocks.risk).toHaveBeenCalledWith(job.user_id, "agent:orders-idor", job.repository_id);
    expect(completed()).toEqual([{
      p_user: job.user_id, p_job: job.id, p_token: job.lease_token, p_status: "opened",
      p_url: "https://github.com/acme/app/pull/9", p_number: 9, p_failure: null,
    }]);
  });

  it("opens a fix-card PR with the customer's reviewed edit", async () => {
    mocks.receipt.mockResolvedValue(receipt({ action: "finding-fix-pr", finding_id: "scan:open-table", edited_content: "-- reviewed" }));
    await executeRepairJob(job);
    expect(mocks.finding).toHaveBeenCalledWith(job.user_id, "scan:open-table", "-- reviewed", job.repository_id);
    expect(completed()[0]).toMatchObject({ p_status: "opened", p_number: 10 });
  });

  it("records a permanent refusal as failed without retrying", async () => {
    mocks.risk.mockResolvedValue({ status: "failed", code: "finding_unavailable" });
    await executeRepairJob(job);
    expect(completed()).toEqual([expect.objectContaining({ p_status: "failed", p_failure: "finding_unavailable", p_url: null })]);
  });

  it("marks an ambiguous GitHub failure uncertain and retries", async () => {
    mocks.risk.mockRejectedValue(new Error("socket hang up"));
    await expect(executeRepairJob(job)).rejects.toThrow("socket hang up");
    expect(completed()).toEqual([expect.objectContaining({ p_status: "uncertain", p_failure: "delivery_unconfirmed" })]);
  });

  it("does nothing further once the receipt already has a final outcome", async () => {
    mocks.receipt.mockResolvedValue(receipt({ status: "opened" }));
    await executeRepairJob(job);
    expect(mocks.risk).not.toHaveBeenCalled();
    expect(completed()).toEqual([]);
  });

  it("refuses a receipt that does not belong to this job's tenant and repository", async () => {
    mocks.receipt.mockResolvedValue(receipt({ repository_id: "55555555-5555-4555-8555-555555555555" }));
    await expect(executeRepairJob(job)).rejects.toBeInstanceOf(PermanentJobError);
    expect(mocks.risk).not.toHaveBeenCalled();
  });

  it("fails when the lease was lost before the outcome could be recorded", async () => {
    mocks.rpc.mockResolvedValue({ data: false, error: null });
    await expect(executeRepairJob(job)).rejects.toThrow("receipt");
  });
});
