import { beforeEach, describe, expect, it, vi } from "vitest";

// X2 (2026-10-12): traffic seen by the customer-side snippet reaches the
// rate-limit offer. Each repository's flagged-source counts are written as
// observations with source "snippet", replacing the previous set, so a
// stopped attack stops being offered.
const collectSnippetHotPaths = vi.fn();
const rpc = vi.fn();
vi.mock("./graphFacts", () => ({ collectSnippetHotPaths }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ rpc }) }));

const { syncSnippetObservations } = await import("./snippetObservations");

describe("syncSnippetObservations", () => {
  beforeEach(() => {
    collectSnippetHotPaths.mockReset();
    rpc.mockReset().mockResolvedValue({ data: 2, error: null });
  });

  it("writes this repository's flagged snippet counts as snippet observations", async () => {
    collectSnippetHotPaths.mockResolvedValue([{ path: "/api/login", suspiciousRequests: 40 }, { path: "/api/orders/1", suspiciousRequests: 3 }]);
    expect(await syncSnippetObservations("u1", "r1")).toBe(2);
    expect(collectSnippetHotPaths).toHaveBeenCalledWith("u1", "r1");
    expect(rpc).toHaveBeenCalledWith("replace_traffic_observations", { p_user: "u1", p_repository: "r1", p_source: "snippet",
      p_paths: [{ path: "/api/login", suspiciousRequests: 40 }, { path: "/api/orders/1", suspiciousRequests: 3 }] });
  });

  it("clears the set when nothing is flagged any more", async () => {
    collectSnippetHotPaths.mockResolvedValue([]);
    rpc.mockResolvedValue({ data: 0, error: null });
    expect(await syncSnippetObservations("u1", "r1")).toBe(0);
    expect(rpc).toHaveBeenCalledWith("replace_traffic_observations", expect.objectContaining({ p_source: "snippet", p_paths: [] }));
  });

  it("fails loudly when the write is refused", async () => {
    collectSnippetHotPaths.mockResolvedValue([]);
    rpc.mockResolvedValue({ data: null, error: { message: "repository unavailable" } });
    await expect(syncSnippetObservations("u1", "r1")).rejects.toThrow("snippet observations not written");
  });
});
