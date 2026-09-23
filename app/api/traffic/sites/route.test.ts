import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({ user: vi.fn(), create: vi.fn(), revoke: vi.fn(), list: vi.fn() }));
vi.mock("@/lib/deep/proGate", () => ({ requireProUser: mocks.user }));
vi.mock("@/lib/traffic/sites", () => ({ createTrafficSite: mocks.create, revokeTrafficSite: mocks.revoke, listTrafficSites: mocks.list }));

import { DELETE, GET, POST } from "./route";

const url = "https://shiplock.dev/api/traffic/sites";
const repo = "33333333-3333-4333-8333-333333333333";
const token = "11111111-1111-4111-8111-111111111111";
const post = (body: unknown, origin = "https://shiplock.dev") => new Request(url, { method: "POST",
  headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });

beforeEach(() => { vi.clearAllMocks(); mocks.user.mockResolvedValue({ userId: "u1", email: null }); });

describe("/api/traffic/sites (2F-2b)", () => {
  it("lists the caller's sites without tokens", async () => {
    mocks.list.mockResolvedValue([{ siteId: "s1", host: "app.example.com", repository: "acme/app", createdAt: "x" }]);
    const res = await GET();
    expect(await res.json()).toEqual({ sites: [{ siteId: "s1", host: "app.example.com", repository: "acme/app", createdAt: "x" }] });
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("creates a site once and returns its token and snippets", async () => {
    mocks.create.mockResolvedValue({ siteId: "s1", ingestToken: token });
    const res = await POST(post({ repositoryId: repo, host: "app.example.com" }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ingestToken).toBe(token);
    expect(body.snippets.nextjs).toContain(token);
    expect(mocks.create).toHaveBeenCalledWith("u1", repo, "app.example.com");
  });

  it("refuses cross-site, signed-out, and malformed requests before writing", async () => {
    expect((await POST(post({ repositoryId: repo, host: "a.example.com" }, "https://evil.example"))).status).toBe(403);
    expect((await POST(post({ repositoryId: "nope", host: "a.example.com" }))).status).toBe(400);
    mocks.user.mockResolvedValue(null);
    expect((await POST(post({ repositoryId: repo, host: "a.example.com" }))).status).toBe(403);
    expect(mocks.create).not.toHaveBeenCalled();
  });

  it("explains a host bound to another repository or an invalid host", async () => {
    mocks.create.mockRejectedValue(new Error("host_already_bound"));
    expect((await POST(post({ repositoryId: repo, host: "app.example.com" }))).status).toBe(409);
    mocks.create.mockRejectedValue(new Error("invalid_host"));
    expect((await POST(post({ repositoryId: repo, host: "localhost" }))).status).toBe(400);
  });

  it("revokes only through a same-origin request", async () => {
    mocks.revoke.mockResolvedValue(true);
    const del = (origin: string) => new Request(`${url}?id=22222222-2222-4222-8222-222222222222`, { method: "DELETE", headers: { origin } });
    expect((await DELETE(del("https://evil.example"))).status).toBe(403);
    expect((await DELETE(del("https://shiplock.dev"))).status).toBe(200);
    expect(mocks.revoke).toHaveBeenCalledWith("u1", "22222222-2222-4222-8222-222222222222");
  });
});
