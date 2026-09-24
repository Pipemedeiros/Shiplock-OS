import { beforeEach, describe, expect, it, vi } from "vitest";

// Q13: the preview resolves a fix's repository exactly as each click route
// does, from server records, never from the request.
const state = vi.hoisted(() => ({ rows: {} as Record<string, unknown>, open: vi.fn(), fix: vi.fn(), filters: [] as unknown[][] }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const result = () => Promise.resolve({ data: state.rows[table] ?? null, error: null });
  Object.assign(q, { select: () => q, eq: (...a: unknown[]) => { state.filters.push([table, ...a]); return q; }, maybeSingle: result,
    then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => result().then(res, rej) });
  return q;
} }) }));
vi.mock("@/lib/agent/dashboardData", () => ({ getOpenFindings: state.open }));
vi.mock("@/lib/fixes/findings", () => ({ getFixFindings: state.fix }));
vi.mock("@/lib/fixes/lane", () => ({ fixLane: (f: { id: string }) => ({ method: f.id.startsWith("dep:") ? "dep-pr" : "pr" }) }));

import { resolveRepairTarget } from "./repairTarget";

const R1 = "33333333-3333-4333-8333-333333333333";
beforeEach(() => { vi.clearAllMocks(); state.rows = {}; state.filters = []; });

describe("resolveRepairTarget (Q13)", () => {
  it("fix before merge: the review's repository, owner-scoped, same-repository only", async () => {
    state.rows.pull_request_reviews = { repository_id: R1, same_repository: true, head_ref: "feat", findings: [{ id: "f" }] };
    expect(await resolveRepairTarget("u1", { lane: "pull-request", reviewId: "v", findingId: "f" }))
      .toEqual({ ok: true, target: { action: "pr-fix-pr", repositoryId: R1, reviewId: "v", findingId: "f" } });
    expect(state.filters).toContainEqual(["pull_request_reviews", "user_id", "u1"]);
    state.rows.pull_request_reviews = { repository_id: R1, same_repository: false, head_ref: "feat", findings: [{ id: "f" }] };
    expect(await resolveRepairTarget("u1", { lane: "pull-request", reviewId: "v", findingId: "f" })).toEqual({ ok: false, code: "fork" });
    state.rows.pull_request_reviews = { repository_id: R1, same_repository: true, head_ref: "feat", findings: [] };
    expect(await resolveRepairTarget("u1", { lane: "pull-request", reviewId: "v", findingId: "f" })).toEqual({ ok: false, code: "not_found" });
  });
  it("AI fix: the task's repository, only for a received proposal", async () => {
    state.rows.intelligence_tasks = { repository_id: R1, status: "proposal_received", result: { edits: [{}] } };
    expect(await resolveRepairTarget("u1", { lane: "ai", taskId: "t" })).toEqual({ ok: true, target: { action: "ai-fix-pr", repositoryId: R1, taskId: "t" } });
    state.rows.intelligence_tasks = { repository_id: R1, status: "pending", result: null };
    expect(await resolveRepairTarget("u1", { lane: "ai", taskId: "t" })).toEqual({ ok: false, code: "no_proposal" });
    state.rows.intelligence_tasks = null;
    expect(await resolveRepairTarget("u1", { lane: "ai", taskId: "t" })).toEqual({ ok: false, code: "not_found" });
  });
  it("risk: the finding's selected repository", async () => {
    state.open.mockResolvedValue([{ id: "f", repository: "acme/app", fixKind: "pr", fixPrUrl: null }]);
    state.rows.repositories = { id: R1 };
    expect(await resolveRepairTarget("u1", { lane: "risk", findingId: "f" })).toEqual({ ok: true, target: { action: "risk-fix-pr", repositoryId: R1, findingId: "f" } });
    state.open.mockResolvedValue([{ id: "f", repository: "acme/app", fixKind: "manual", fixPrUrl: null }]);
    expect(await resolveRepairTarget("u1", { lane: "risk", findingId: "f" })).toEqual({ ok: false, code: "manual" });
    state.open.mockResolvedValue([{ id: "f", repository: "acme/app", fixKind: "pr", fixPrUrl: "https://github.com/acme/app/pull/2" }]);
    expect(await resolveRepairTarget("u1", { lane: "risk", findingId: "f" })).toEqual({ ok: false, code: "already_open", url: "https://github.com/acme/app/pull/2" });
    state.open.mockResolvedValue([{ id: "f", repository: "acme/app", fixKind: "pr", fixPrUrl: null }]);
    state.rows.repositories = null;
    expect(await resolveRepairTarget("u1", { lane: "risk", findingId: "f" })).toEqual({ ok: false, code: "repository_unselected" });
  });
  it("fix card: the scoped or only selected repository, dependency findings become one bump", async () => {
    state.rows.repositories = [{ id: R1, full_name: "acme/app" }];
    state.fix.mockResolvedValue([{ id: "f" }, { id: "dep:lodash" }]);
    expect(await resolveRepairTarget("u1", { lane: "finding", findingId: "f", editedContent: "e" }))
      .toEqual({ ok: true, target: { action: "finding-fix-pr", repositoryId: R1, findingId: "f", editedContent: "e" } });
    expect(await resolveRepairTarget("u1", { lane: "finding", findingId: "dep:lodash" })).toEqual({ ok: true, target: { action: "dependency-bump-pr", repositoryId: R1 } });
    state.rows.repositories = [{ id: R1, full_name: "acme/app" }, { id: "other", full_name: "acme/two" }];
    expect(await resolveRepairTarget("u1", { lane: "finding", findingId: "f" })).toEqual({ ok: false, code: "choose_repository" });
    expect(await resolveRepairTarget("u1", { lane: "finding", findingId: "missing" })).toEqual({ ok: false, code: "not_found" });
  });
});
