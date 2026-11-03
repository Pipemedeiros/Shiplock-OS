import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), request: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/jobs/repairAction", () => ({ requestRepairAction: mocks.request }));

import { POST } from "./route";

const repositoryId = "33333333-3333-4333-8333-333333333333";
const post = (body: unknown, origin = "https://shiplock.dev") => POST(new Request("https://shiplock.dev/api/fix/rate-limit", {
  method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body),
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.request.mockResolvedValue("66666666-6666-4666-8666-666666666666");
});

describe("POST /api/fix/rate-limit", () => {
  it("refuses cross-site and signed-out requests before any work", async () => {
    expect((await post({ repositoryId, routeFile: "app/api/x/route.ts" }, "https://evil.example")).status).toBe(403);
    mocks.pro.mockResolvedValue(null);
    expect((await post({ repositoryId, routeFile: "app/api/x/route.ts" })).status).toBe(401);
    expect(mocks.request).not.toHaveBeenCalled();
  });
  it("accepts only an App Router route file", async () => {
    for (const routeFile of ["pages/api/x.ts", "app/api/x/page.tsx", "../etc/passwd", "app/api/x y/route.ts", ""]) {
      expect((await post({ repositoryId, routeFile })).status).toBe(400);
    }
    expect(mocks.request).not.toHaveBeenCalled();
  });
  it("queues one receipted repair for the clicked route", async () => {
    const res = await post({ repositoryId, routeFile: "src/app/api/orders/[id]/route.ts" });
    expect(res.status).toBe(202);
    expect(await res.json()).toEqual({ receiptId: "66666666-6666-4666-8666-666666666666", status: "queued" });
    expect(mocks.request).toHaveBeenCalledWith({ userId: "u1", repositoryId, action: "rate-limit-pr",
      findingId: "traffic:src/app/api/orders/[id]/route.ts", editedContent: null });
  });
  it("says so when there is no observed traffic for that repository", async () => {
    mocks.request.mockRejectedValue(new Error("The fix could not be queued"));
    expect((await post({ repositoryId, routeFile: "app/api/x/route.ts" })).status).toBe(503);
  });
});
