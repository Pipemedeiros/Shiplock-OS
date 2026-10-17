import { beforeEach, describe, expect, it, vi } from "vitest";

// G3: the founder confirms the address the outside view reads. Suggestions
// come from GitHub; nothing is probed until a confirm, and the confirm starts
// the read at once (responsive) instead of waiting for the 48 hour pass.
const mocks = vi.hoisted(() => ({ user: vi.fn(), state: vi.fn(), set: vi.fn(), clear: vi.fn(), recheck: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/deep/appUrlStore", () => ({ getAppUrlState: mocks.state, setAppUrl: mocks.set, clearAppUrl: mocks.clear }));
vi.mock("@/lib/jobs/manualRecheck", () => ({ queueCustomerRecheck: mocks.recheck }));

import { DELETE, GET, POST } from "./route";

const url = "https://shiplock.dev/api/app-url";
const req = (method: string, body?: unknown, origin = "https://shiplock.dev") => new Request(url, { method,
  headers: { "content-type": "application/json", origin }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

beforeEach(() => { vi.clearAllMocks(); mocks.user.mockResolvedValue({ userId: "u1", email: null }); mocks.recheck.mockResolvedValue("job1"); });

describe("/api/app-url", () => {
  it("returns the confirmed address and GitHub's suggestions, never cached", async () => {
    mocks.state.mockResolvedValue({ current: null, suggestions: [{ repository: "acme/app", url: "https://acme.com" }] });
    const res = await GET();
    expect(await res.json()).toEqual({ current: null, suggestions: [{ repository: "acme/app", url: "https://acme.com" }] });
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(mocks.state).toHaveBeenCalledWith("u1");
  });

  it("confirms an address and starts the outside view at once", async () => {
    mocks.set.mockResolvedValue("https://acme.com");
    const res = await POST(req("POST", { url: "https://acme.com/login" }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ url: "https://acme.com", recheck: "job1" });
    expect(mocks.set).toHaveBeenCalledWith("u1", "https://acme.com/login", null);
    expect(mocks.recheck).toHaveBeenCalledWith("u1", "app-surface");
  });

  it("passes the repository the founder confirmed the address for, and refuses one not selected", async () => {
    mocks.set.mockResolvedValue("https://acme.com");
    expect((await POST(req("POST", { url: "https://acme.com", repository: "acme/app" }))).status).toBe(200);
    expect(mocks.set).toHaveBeenCalledWith("u1", "https://acme.com", "acme/app");
    mocks.set.mockRejectedValue(new Error("invalid_repository"));
    const res = await POST(req("POST", { url: "https://acme.com", repository: "evil/other" }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("Choose one of the repositories you selected in ShipLock.");
    expect((await POST(req("POST", { url: "https://acme.com", repository: 7 }))).status).toBe(400);
  });

  it("keeps the address when the recheck cannot be queued, and says so", async () => {
    mocks.set.mockResolvedValue("https://acme.com");
    mocks.recheck.mockRejectedValue(new Error("queue down"));
    expect(await (await POST(req("POST", { url: "https://acme.com" }))).json()).toEqual({ url: "https://acme.com", recheck: null });
  });

  it("refuses a private, malformed or non https address in plain words", async () => {
    mocks.set.mockRejectedValue(new Error("invalid_url"));
    const res = await POST(req("POST", { url: "http://10.0.0.1" }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("Enter your app's public https address, like https://app.example.com.");
    expect((await POST(req("POST", { nope: 1 }))).status).toBe(400);
  });

  it("refuses cross-site and signed-out requests before reading or writing", async () => {
    expect((await POST(req("POST", { url: "https://acme.com" }, "https://evil.example"))).status).toBe(403);
    expect((await DELETE(req("DELETE", undefined, "https://evil.example"))).status).toBe(403);
    mocks.user.mockResolvedValue(null);
    expect((await POST(req("POST", { url: "https://acme.com" }))).status).toBe(403);
    expect((await GET()).status).toBe(403);
    expect(mocks.set).not.toHaveBeenCalled();
    expect(mocks.clear).not.toHaveBeenCalled();
  });

  it("forgets the address so nothing is probed", async () => {
    mocks.clear.mockResolvedValue(undefined);
    expect(await (await DELETE(req("DELETE"))).json()).toEqual({ url: null });
    expect(mocks.clear).toHaveBeenCalledWith("u1");
  });
});
