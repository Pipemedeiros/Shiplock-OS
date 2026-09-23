import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), status: vi.fn(), save: vi.fn(), remove: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/intelligence/credential", async (original) => ({
  ...(await original<typeof import("@/lib/intelligence/credential")>()),
  getApiKeyStatus: mocks.status, saveApiKey: mocks.save, removeApiKey: mocks.remove,
}));

import { DELETE, GET, POST } from "./route";

const url = "https://shiplock.dev/api/intelligence/credential";
const key = "sk-ant-api03-" + "B".repeat(60) + "Qr_7";
const post = (body: unknown, origin = "https://shiplock.dev") => new Request(url, { method: "POST",
  headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });
const del = (origin = "https://shiplock.dev") => new Request(url, { method: "DELETE", headers: { origin } });

beforeEach(() => { vi.clearAllMocks(); mocks.user.mockResolvedValue({ userId: "u1", email: null }); });

describe("/api/intelligence/credential (10B-2e)", () => {
  it("requires sign-in", async () => {
    mocks.user.mockResolvedValue(null);
    expect((await GET()).status).toBe(403);
    expect((await POST(post({ apiKey: key }))).status).toBe(403);
    expect((await DELETE(del())).status).toBe(403);
    expect(mocks.save).not.toHaveBeenCalled();
  });

  it("returns status only, uncached", async () => {
    mocks.status.mockResolvedValue({ stored: true, hint: "Qr_7", savedAt: "x" });
    const response = await GET();
    expect(await response.json()).toEqual({ stored: true, hint: "Qr_7", savedAt: "x" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("refuses cross-site, non-JSON, and malformed keys before storing", async () => {
    expect((await POST(post({ apiKey: key }, "https://evil.example"))).status).toBe(403);
    expect((await POST(new Request(url, { method: "POST", headers: { origin: "https://shiplock.dev" }, body: "x" }))).status).toBe(415);
    expect((await POST(post({ apiKey: "sk-live-nope" }))).status).toBe(400);
    expect((await DELETE(del("https://evil.example"))).status).toBe(403);
    expect(mocks.save).not.toHaveBeenCalled();
    expect(mocks.remove).not.toHaveBeenCalled();
  });

  it("saves and never echoes the key; removes on DELETE", async () => {
    mocks.save.mockResolvedValue({ stored: true, hint: "Qr_7" });
    const saved = await POST(post({ apiKey: key }));
    const text = await saved.text();
    expect(saved.status).toBe(200);
    expect(text).not.toContain("sk-ant");
    expect(mocks.save).toHaveBeenCalledWith("u1", key);
    expect((await DELETE(del())).status).toBe(200);
    expect(mocks.remove).toHaveBeenCalledWith("u1");
  });

  it("fails closed on storage errors without detail", async () => {
    mocks.save.mockRejectedValue(new Error("credential_unwritable"));
    const response = await POST(post({ apiKey: key }));
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("credential_unwritable");
  });
});
