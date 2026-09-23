import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ tasks: vi.fn(), scans: vi.fn(), connection: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const query: Record<string, unknown> = {};
  for (const name of ["select", "eq", "gt", "order", "limit", "in"]) {
    query[name] = (...args: unknown[]) => { state.filters(table, name, ...args); return query; };
  }
  query.then = (resolve: (v: unknown) => unknown) => resolve(table === "intelligence_tasks" ? state.tasks() : state.scans());
  return query;
} }) }));
vi.mock("./connection", () => ({ getIntelligenceConnection: state.connection }));

import { aiCheckForPullRequest, aiStateOf, getAiActivity, pausedReason, type AiCheck } from "./activity";

const now = Date.parse("2026-09-23T12:00:00Z");
const approved = { state: "approved", host: "codex", deepScan: "weekly", prScan: "every_pr", runTokenBudget: 1000,
  monthlyTokenBudget: 10000, approvedAt: "x", budgetEnforcement: "advisory", pullRequests: "each_needs_a_click", monthReportedTokens: 0 } as const;
const job = "44444444-4444-4444-8444-444444444444";

beforeEach(() => {
  vi.clearAllMocks();
  state.connection.mockResolvedValue(approved);
  state.tasks.mockReturnValue({ data: [
    { id: "t1", commit_sha: "a".repeat(40), status: "pending", expires_at: "2026-09-23T20:00:00Z", created_at: "2026-09-23T10:00:00Z",
      idempotency_key: `job:${job}`, repositories: { full_name: "acme/app" } },
    { id: "t2", commit_sha: "b".repeat(40), status: "pending", expires_at: "2026-09-22T20:00:00Z", created_at: "2026-09-22T10:00:00Z",
      idempotency_key: "manual-1", repositories: { full_name: "acme/app" } },
  ], error: null });
  state.scans.mockReturnValue({ data: [{ job_id: job, scan: "pr", pull_request_number: 7 }], error: null });
});

describe("AI check states (10B-2d)", () => {
  it("never derives a clean state: unanswered work is pending or expired", () => {
    expect(aiStateOf("pending", "2026-09-23T20:00:00Z", now)).toBe("pending");
    expect(aiStateOf("pending", "2026-09-23T11:00:00Z", now)).toBe("expired");
    expect(aiStateOf("cancelled", "2026-09-23T20:00:00Z", now)).toBe("withdrawn");
    expect(aiStateOf("proposal_received", "2026-09-22T00:00:00Z", now)).toBe("proposal");
    expect(aiStateOf("needs_human", "2026-09-22T00:00:00Z", now)).toBe("needs_human");
    expect(aiStateOf("unavailable", "2026-09-22T00:00:00Z", now)).toBe("unavailable");
  });

  it("explains why new AI checks are not being created", () => {
    expect(pausedReason({ state: "none" })).toBe("not_connected");
    expect(pausedReason({ ...approved, state: "revoked" })).toBe("revoked");
    expect(pausedReason({ ...approved, monthReportedTokens: 10000 })).toBe("budget");
    expect(pausedReason(approved)).toBeNull();
  });

  it("lists the caller's recent AI checks with their PR, newest first", async () => {
    const activity = await getAiActivity("u1", now);
    expect(activity).toMatchObject({ available: true, paused: null, checks: [
      { taskId: "t1", repository: "acme/app", kind: "pr", pullRequest: 7, state: "pending" },
      { taskId: "t2", repository: "acme/app", kind: "other", pullRequest: null, state: "expired" },
    ] });
    expect(state.filters).toHaveBeenCalledWith("intelligence_tasks", "eq", "user_id", "u1");
    expect(state.filters).toHaveBeenCalledWith("intelligence_scan_jobs", "eq", "user_id", "u1");
    expect(state.filters).toHaveBeenCalledWith("intelligence_scan_jobs", "in", "job_id", [job]);
  });

  it("reports unavailable rather than an empty, clean-looking list when storage fails", async () => {
    state.tasks.mockReturnValue({ data: null, error: { message: "down" } });
    expect(await getAiActivity("u1", now)).toEqual({ available: false });
    state.tasks.mockReturnValue({ data: [], error: null });
    state.connection.mockRejectedValue(new Error("connection_unreadable"));
    expect(await getAiActivity("u1", now)).toEqual({ available: false });
  });

  it("finds the newest AI check for a pull request", () => {
    const base = { repository: "acme/app", kind: "pr", commit: "a", createdAt: "x", expiresAt: "x" } as const;
    const checks: AiCheck[] = [
      { ...base, taskId: "new", pullRequest: 7, state: "pending" },
      { ...base, taskId: "old", pullRequest: 7, state: "expired" },
      { ...base, taskId: "other", repository: "acme/web", pullRequest: 7, state: "proposal" },
    ];
    expect(aiCheckForPullRequest(checks, "acme/app", 7)?.taskId).toBe("new");
    expect(aiCheckForPullRequest(checks, "acme/app", 8)).toBeNull();
  });
});
