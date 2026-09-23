import { beforeEach, describe, expect, it, vi } from "vitest";

const rpc = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

import { purgeIntelligenceTasks } from "./retention";

beforeEach(() => { rpc.mockReset(); });

describe("purgeIntelligenceTasks (10B-1d)", () => {
  it("runs the bounded purge and reports how many tasks it removed", async () => {
    rpc.mockResolvedValue({ data: 3, error: null });
    expect(await purgeIntelligenceTasks()).toEqual({ ok: true, purged: 3 });
    expect(rpc).toHaveBeenCalledWith("purge_intelligence_tasks");
  });

  it("is fail-soft so the daily cron still completes", async () => {
    rpc.mockResolvedValue({ data: null, error: { message: "down" } });
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await purgeIntelligenceTasks()).toEqual({ ok: false, purged: 0 });
    log.mockRestore();
  });
});
