import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), task: vi.fn(), request: vi.fn(), filters: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestRepairAction: mocks.request }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q = { select: () => q, eq: (k: string, v: unknown) => { mocks.filters(table, k, v); return q; }, maybeSingle: mocks.task };
  return q;
} }) }));

import { POST } from "./route";

const id = "11111111-1111-4111-8111-111111111111";
const repo = "33333333-3333-4333-8333-333333333333";
const params = (value = id) => ({ params: Promise.resolve({ id: value }) });
const req = (origin = "https://shiplock.dev") => new Request(`https://shiplock.dev/api/intelligence/tasks/${id}/fix`, { method: "POST", headers: { origin } });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.user.mockResolvedValue({ userId: "u1", email: null });
  mocks.task.mockResolvedValue({ data: { repository_id: repo, status: "proposal_received", result: { edits: [{ path: "next.config.ts" }] } }, error: null });
  mocks.request.mockResolvedValue("receipt-1");
});

describe("POST /api/intelligence/tasks/[id]/fix", () => {
  it("queues one receipted PR for the owner's answered proposal", async () => {
    const res = await POST(req(), params());
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ receiptId: "receipt-1", status: "queued" });
    expect(mocks.request).toHaveBeenCalledWith({ userId: "u1", repositoryId: repo, action: "ai-fix-pr", findingId: id, editedContent: null, taskId: id });
    expect(mocks.filters).toHaveBeenCalledWith("intelligence_tasks", "user_id", "u1");
  });

  it("requires sign-in and a same-origin click", async () => {
    mocks.user.mockResolvedValue(null);
    expect((await POST(req(), params())).status).toBe(401);
    mocks.user.mockResolvedValue({ userId: "u1", email: null });
    expect((await POST(req("https://evil.example"), params())).status).toBe(403);
    expect((await POST(req(), params("../x"))).status).toBe(400);
    expect(mocks.request).not.toHaveBeenCalled();
  });

  it("refuses anything that is not an answered proposal with edits", async () => {
    mocks.task.mockResolvedValue({ data: { repository_id: repo, status: "needs_human", result: { edits: [] } }, error: null });
    expect((await POST(req(), params())).status).toBe(409);
    mocks.task.mockResolvedValue({ data: null, error: null });
    expect((await POST(req(), params())).status).toBe(404);
    mocks.task.mockResolvedValue({ data: null, error: { message: "down" } });
    expect((await POST(req(), params())).status).toBe(503);
    expect(mocks.request).not.toHaveBeenCalled();
  });
});
