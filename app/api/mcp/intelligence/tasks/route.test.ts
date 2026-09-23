import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";

const mocks = vi.hoisted(() => ({ auth: vi.fn(), list: vi.fn() }));
vi.mock("@/lib/mcpAuth", () => ({ authMcp: mocks.auth }));
vi.mock("@/lib/intelligence/tasks", () => ({ listPendingIntelligenceTasks: mocks.list }));

import { GET } from "./route";

const req = () => new NextRequest("https://shiplock.dev/api/mcp/intelligence/tasks");
beforeEach(() => {
  vi.clearAllMocks();
  mocks.auth.mockResolvedValue({ userId: "u1" });
  mocks.list.mockResolvedValue([{ taskId: "t1" }]);
});

describe("GET /api/mcp/intelligence/tasks (10B-2a)", () => {
  it("lists the PAT owner's pending tasks", async () => {
    const res = await GET(req());
    expect(await res.json()).toEqual({ tasks: [{ taskId: "t1" }] });
    expect(mocks.list).toHaveBeenCalledWith("u1");
    expect(res.headers.get("Cache-Control")).toBe("no-store");
  });
  it("requires a PAT and hides storage errors", async () => {
    mocks.list.mockRejectedValue(new Error("db password leaked"));
    expect(await (await GET(req())).json()).toEqual({ error: "tasks_unreadable" });
    mocks.auth.mockResolvedValue({ error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) });
    expect((await GET(req())).status).toBe(401);
  });
});
