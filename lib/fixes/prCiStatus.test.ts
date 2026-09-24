import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ runs: vi.fn(), token: vi.fn(), profile: vi.fn() }));
vi.mock("@/lib/deep/github", () => ({ listPullRequestCheckRuns: mocks.runs, getInstallationToken: mocks.token }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const q = { select: () => q, eq: () => q, maybeSingle: mocks.profile };
  return q;
} }) }));

import { ciState, getCiStatuses } from "./prCiStatus";

const run = (status: string, conclusion: string | null = null) => ({ status, conclusion });

describe("ciState (Q2 / 8-CI)", () => {
  it("maps the customer's check runs, never counting absence as passing", () => {
    expect(ciState([])).toBe("none_visible");
    expect(ciState([run("completed", "success"), run("completed", "skipped"), run("completed", "neutral")])).toBe("passing");
    expect(ciState([run("completed", "success"), run("in_progress")])).toBe("pending");
    expect(ciState([run("queued"), run("completed", "failure")])).toBe("failing");
    for (const bad of ["failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"]) {
      expect(ciState([run("completed", bad)])).toBe("failing");
    }
  });
});

const pr = (id: string, number: number, mergedAt: string | null = null) => ({ id, lane: "Fix", repository: "acme/app", number,
  url: `https://github.com/acme/app/pull/${number}`, mergedAt, requestedAt: "2026-09-20T10:00:00.000Z" });

describe("getCiStatuses", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.profile.mockResolvedValue({ data: { github_installation_id: 42 }, error: null });
    mocks.token.mockResolvedValue("tok");
    mocks.runs.mockResolvedValue([run("completed", "success")]);
  });

  it("reads only open pull requests, at most ten, read-only", async () => {
    const prs = [pr("m", 1, "2026-09-21T00:00:00.000Z"), ...Array.from({ length: 12 }, (_, i) => pr(`p${i}`, i + 2))];
    const result = await getCiStatuses("u1", prs);
    expect(result.m).toBeUndefined();
    expect(Object.keys(result)).toHaveLength(12);
    expect(mocks.runs).toHaveBeenCalledTimes(10);
    expect(result.p0).toBe("passing");
    expect(result.p11).toBe("unknown");
    expect(mocks.token).toHaveBeenCalledWith(42);
  });

  it("marks a GitHub error, a missing installation, or an overrun budget as unknown", async () => {
    mocks.runs.mockRejectedValueOnce(new Error("HTTP 502")).mockImplementation(() => new Promise(() => {}));
    expect(await getCiStatuses("u1", [pr("a", 1), pr("b", 2)], { budgetMs: 20 })).toEqual({ a: "unknown", b: "unknown" });
    mocks.profile.mockResolvedValue({ data: { github_installation_id: null }, error: null });
    expect(await getCiStatuses("u1", [pr("a", 1)])).toEqual({ a: "unknown" });
  });
});
