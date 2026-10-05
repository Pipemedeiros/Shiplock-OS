import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), status: vi.fn(), remove: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/intelligence/credential", () => ({ getApiKeyStatus: mocks.status, removeApiKey: mocks.remove }));

import * as route from "./route";

const url = "https://shiplock.dev/api/intelligence/credential";
const del = (origin = "https://shiplock.dev") => new Request(url, { method: "DELETE", headers: { origin } });

beforeEach(() => { vi.clearAllMocks(); mocks.user.mockResolvedValue({ userId: "u1", email: null }); });

// The customer API-key mode is retired (Felipe, 2026-10-01): a stored key can
// be seen by its last 4 characters and erased, never saved again.
describe("/api/intelligence/credential", () => {
  it("accepts no new key", () => {
    expect("POST" in route).toBe(false);
  });

  it("requires sign-in", async () => {
    mocks.user.mockResolvedValue(null);
    expect((await route.GET()).status).toBe(403);
    expect((await route.DELETE(del())).status).toBe(403);
    expect(mocks.remove).not.toHaveBeenCalled();
  });

  it("returns status only, uncached", async () => {
    mocks.status.mockResolvedValue({ stored: true, hint: "Qr_7", savedAt: "x" });
    const response = await route.GET();
    expect(await response.json()).toEqual({ stored: true, hint: "Qr_7", savedAt: "x" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("removes on a same-site DELETE only", async () => {
    expect((await route.DELETE(del("https://evil.example"))).status).toBe(403);
    expect(mocks.remove).not.toHaveBeenCalled();
    expect((await route.DELETE(del())).status).toBe(200);
    expect(mocks.remove).toHaveBeenCalledWith("u1");
  });

  it("fails closed on storage errors without detail", async () => {
    mocks.remove.mockRejectedValue(new Error("credential_unwritable"));
    const response = await route.DELETE(del());
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("credential_unwritable");
  });
});
