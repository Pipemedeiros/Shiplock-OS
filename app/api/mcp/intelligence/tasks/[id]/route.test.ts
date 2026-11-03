import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

// A customer's host reads and answers its own tasks with a ShipLock PAT.
const mocks = vi.hoisted(() => ({ auth: vi.fn(), get: vi.fn(), submit: vi.fn() }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: mocks.auth }));
vi.mock("@/lib/intelligence/tasks", () => ({ getIntelligenceTask: mocks.get, submitIntelligenceResult: mocks.submit }));

import { GET } from "./route";
import { POST } from "./result/route";

const id = "11111111-1111-4111-8111-111111111111";
const params = { params: Promise.resolve({ id }) };
const req = (body?: unknown) => new NextRequest(`https://shiplock.dev/api/mcp/intelligence/tasks/${id}`, body === undefined ? {} : { method: "POST", body: JSON.stringify(body) });

beforeEach(() => {
  vi.clearAllMocks();
  mocks.auth.mockResolvedValue({ userId: "u1" });
  mocks.get.mockResolvedValue({ identity: { taskId: id }, status: "pending" });
  mocks.submit.mockResolvedValue({ taskId: id, status: "proposal_received", outcome: "accepted" });
});

describe("GET /api/mcp/intelligence/tasks/[id]", () => {
  it("returns the PAT owner's task", async () => {
    const res = await GET(req(), params);
    expect(res.status).toBe(200);
    expect(mocks.get).toHaveBeenCalledWith("u1", id);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
  it("hides another tenant's task and requires a PAT", async () => {
    mocks.get.mockResolvedValue(null);
    expect((await GET(req(), params)).status).toBe(404);
    mocks.auth.mockResolvedValue({ error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) });
    expect((await GET(req(), params)).status).toBe(401);
  });
  it("rejects a malformed id", async () => {
    expect((await GET(req(), { params: Promise.resolve({ id: "../x" }) })).status).toBe(400);
  });
});

describe("POST /api/mcp/intelligence/tasks/[id]/result", () => {
  it("submits the host's result for the PAT owner and returns the receipt", async () => {
    const res = await POST(req({ result: { version: 1 } }), params);
    expect(res.status).toBe(200);
    expect(mocks.submit).toHaveBeenCalledWith("u1", id, { version: 1 });
  });
  it.each([
    ["citation_mismatch", 422], ["scope_mismatch", 422], ["task_expired", 409], ["already_completed", 409], ["task_unavailable", 404],
  ])("maps %s to %i without internal detail", async (code, status) => {
    mocks.submit.mockRejectedValue(new Error(code));
    const res = await POST(req({ result: {} }), params);
    expect(res.status).toBe(status);
    expect(await res.json()).toEqual({ error: code });
  });
  it("refuses an agent answering as the API-key host", async () => {
    const res = await POST(req({ result: { version: 1, host: "api" } }), params);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "api_mode_task" });
    expect(mocks.submit).not.toHaveBeenCalled();
  });
  it("hides unexpected errors behind a generic code", async () => {
    mocks.submit.mockRejectedValue(new Error("connection string leaked"));
    expect(await (await POST(req({ result: {} }), params)).json()).toEqual({ error: "submission_failed" });
  });
});
