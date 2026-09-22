import { beforeEach, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));
import { admitDueRepositoryAudits } from "./scheduler";

beforeEach(() => rpc.mockReset().mockResolvedValue({
  data: { eligible: 2, admitted: 2, failed: 0, limited: false }, error: null,
}));

it("admits one bounded UTC-day batch without provider data", async () => {
  await expect(admitDueRepositoryAudits(new Date("2026-09-21T23:30:00Z"), 1_000)).resolves.toEqual({
    eligible: 2, admitted: 2, failed: 0, limited: false,
  });
  expect(rpc).toHaveBeenCalledWith("enqueue_due_repository_audits", {
    p_cutoff: "2026-09-19T23:30:00.000Z",
    p_day: "2026-09-21",
    p_require_paid: false,
    p_limit: 1_000,
  });
});

it("rejects malformed receipts and unsafe batch sizes", async () => {
  rpc.mockResolvedValue({ data: { eligible: 2, admitted: 2, failed: 1, limited: false }, error: null });
  await expect(admitDueRepositoryAudits()).rejects.toThrow();
  await expect(admitDueRepositoryAudits(new Date(), 5_001)).rejects.toThrow();
});
