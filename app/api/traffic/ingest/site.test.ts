import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NextRequest } from "next/server";

// An event that arrives under a traffic site is recorded with that
// site's repository; a legacy account token stays unbound.
const mocks = vi.hoisted(() => ({ resolve: vi.fn(), ingest: vi.fn() }));
vi.mock("@/lib/traffic/sites", () => ({ resolveTrafficToken: mocks.resolve }));
vi.mock("@/lib/traffic/ingest", () => ({ ingestTrafficEvent: mocks.ingest }));
vi.mock("@/lib/traffic/ingestLimit", () => ({ ingestLimiter: { allow: () => true } }));

import { POST } from "./route";

const req = (extra: Record<string, unknown> = {}) => new Request("https://shiplock.dev/api/traffic/ingest", { method: "POST",
  headers: { "content-type": "application/json", "x-site": "11111111-1111-4111-8111-111111111111" },
  body: JSON.stringify({ source_id: "s", path: "/login", method: "POST", ...extra }) }) as unknown as NextRequest;

beforeEach(() => { vi.clearAllMocks(); mocks.ingest.mockResolvedValue({ action: "none" }); });

describe("traffic ingest binds site traffic to its repository", () => {
  it("records a site event with its site and repository", async () => {
    mocks.resolve.mockResolvedValue({ userId: "u1", email: null, siteId: "s1", repositoryId: "r1" });
    expect(await (await POST(req())).json()).toEqual({ ok: true });
    expect(mocks.ingest).toHaveBeenCalledWith(expect.objectContaining({ userId: "u1", siteId: "s1", repositoryId: "r1" }));
  });

  it("records a legacy account event unbound", async () => {
    mocks.resolve.mockResolvedValue({ userId: "u1", email: null, siteId: null, repositoryId: null });
    await POST(req());
    expect(mocks.ingest).toHaveBeenCalledWith(expect.objectContaining({ siteId: null, repositoryId: null }));
  });

  // In-app probes: only a known category reaches detection; anything else
  // (a query string smuggled in, an unknown label) is dropped, not stored.
  it("passes a known probe category and drops anything else", async () => {
    mocks.resolve.mockResolvedValue({ userId: "u1", email: null, siteId: "s1", repositoryId: "r1" });
    await POST(req({ probe: "sqli" }));
    expect(mocks.ingest.mock.calls[0][0].event.probe).toBe("sqli");
    await POST(req({ probe: "id=1' OR '1'='1" }));
    expect(mocks.ingest.mock.calls[1][0].event.probe).toBeNull();
  });

  // 104: the app's answer, from snippets that see it. Only a whole status
  // code in range is kept; anything else is "not reported", never a guess.
  it("passes a response status in range and drops anything else", async () => {
    mocks.resolve.mockResolvedValue({ userId: "u1", email: null, siteId: "s1", repositoryId: "r1" });
    await POST(req({ status: 200 }));
    await POST(req({ status: 99 }));
    await POST(req({ status: "200" }));
    await POST(req({ status: 404.5 }));
    await POST(req());
    expect(mocks.ingest.mock.calls.map((c) => c[0].event.status)).toEqual([200, null, null, null, null]);
  });
});
