import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ pro: vi.fn(), preview: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.pro }));
vi.mock("@/lib/fixes/preview", () => ({ previewRepair: mocks.preview }));
const resolve = vi.hoisted(() => vi.fn());
vi.mock("@/lib/fixes/repairTarget", () => ({ resolveRepairTarget: resolve }));

import { POST } from "./route";

const repositoryId = "33333333-3333-4333-8333-333333333333";
const post = (body: unknown, origin = "https://shiplock.dev") => POST(new Request("https://shiplock.dev/api/fix/preview", {
  method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body),
}));

beforeEach(() => {
  vi.clearAllMocks();
  mocks.pro.mockResolvedValue({ userId: "u1" });
  mocks.preview.mockResolvedValue({ status: "unavailable", code: "not_fixable" });
});

describe("POST /api/fix/preview", () => {
  it("refuses cross-site and signed-out requests before any work", async () => {
    expect((await post({ action: "dependency-bump-pr", repositoryId }, "https://evil.example")).status).toBe(403);
    mocks.pro.mockResolvedValue(null);
    expect((await post({ action: "dependency-bump-pr", repositoryId })).status).toBe(401);
    expect(mocks.preview).not.toHaveBeenCalled();
  });
  it("validates each lane's required fields", async () => {
    for (const body of [{ action: "risk-fix-pr", repositoryId }, { action: "pr-fix-pr", repositoryId, findingId: "f" },
      { action: "ai-fix-pr", repositoryId }, { action: "rate-limit-pr", repositoryId, findingId: "nope" },
      { action: "merge-pr", repositoryId }, { action: "dependency-bump-pr", repositoryId: "x" }]) {
      expect((await post(body)).status).toBe(400);
    }
    expect(mocks.preview).not.toHaveBeenCalled();
  });
  it("returns the caller's preview, uncached", async () => {
    const res = await post({ action: "finding-fix-pr", repositoryId, findingId: "f", editedContent: "e" });
    expect(res.status).toBe(200);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    expect(await res.json()).toEqual({ status: "unavailable", code: "not_fixable" });
    expect(mocks.preview).toHaveBeenCalledWith("u1", { action: "finding-fix-pr", repositoryId, findingId: "f", editedContent: "e" });
  });
  it("resolves a button's identifiers server-side, and 404s what its click route would refuse", async () => {
    resolve.mockResolvedValue({ ok: true, target: { action: "ai-fix-pr", repositoryId, taskId: repositoryId } });
    expect((await post({ lane: "ai", taskId: repositoryId })).status).toBe(200);
    expect(resolve).toHaveBeenCalledWith("u1", { lane: "ai", taskId: repositoryId });
    expect(mocks.preview).toHaveBeenCalledWith("u1", { action: "ai-fix-pr", repositoryId, taskId: repositoryId });
    resolve.mockResolvedValue({ ok: false, code: "manual" });
    expect((await post({ lane: "risk", findingId: "f" })).status).toBe(404);
    resolve.mockResolvedValue({ ok: false, code: "already_open", url: "https://github.com/acme/app/pull/2" });
    expect(await (await post({ lane: "risk", findingId: "f" })).json()).toEqual({ status: "already_open", url: "https://github.com/acme/app/pull/2" });
    expect((await post({ lane: "ai", taskId: "x" })).status).toBe(400);
  });
  it("fails closed when the preview cannot be built", async () => {
    mocks.preview.mockRejectedValue(new Error("GitHub down"));
    expect((await post({ action: "dependency-bump-pr", repositoryId })).status).toBe(503);
  });
});
