import { beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { pruneProviderSnapshots } from "./snapshotRetention";

beforeEach(() => { rpc.mockReset(); });

describe("pruneProviderSnapshots (5A-2)", () => {
  it("returns how many snapshots the daily prune removed", async () => {
    rpc.mockResolvedValue({ data: 4, error: null });
    expect(await pruneProviderSnapshots()).toEqual({ ok: true, pruned: 4 });
    expect(rpc).toHaveBeenCalledWith("prune_provider_snapshots");
  });
  it("fails soft so the daily cron still answers", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    rpc.mockResolvedValue({ data: null, error: { message: "x" } });
    expect(await pruneProviderSnapshots()).toEqual({ ok: false, pruned: 0 });
    log.mockRestore();
  });
});
