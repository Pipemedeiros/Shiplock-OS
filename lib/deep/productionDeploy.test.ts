import { afterEach, describe, expect, it, vi } from "vitest";
import { readProductionDeploy, summarizeDeploys, productionDeploySchema } from "./productionDeploy";

// "Is it live?": hosts that deploy from GitHub (Vercel, Netlify, Render)
// report each production deploy as a GitHub Deployment with its commit. The
// newest successful one is what visitors get; a newer failed one means the
// latest code never shipped. Unreadable is said as such, never as current.
const sha = (c: string) => c.repeat(40);
// The real Vercel shape (read 2026-10-20): environment "Production" with
// production_environment false, so the environment name is what counts.
const d = (id: number, s: string, at: string, extra: Record<string, unknown> = {}) =>
  ({ id, sha: sha(s), environment: "Production", production_environment: false, created_at: at, creator: { login: "vercel[bot]" }, ...extra });

describe("summarizeDeploys", () => {
  it("takes the newest successful production deploy as live and reports a newer failed one", () => {
    const out = summarizeDeploys([d(3, "c", "2026-10-20T12:00:00Z"), d(2, "b", "2026-10-20T11:00:00Z"), d(1, "a", "2026-10-20T10:00:00Z")],
      new Map([[3, { state: "failure", created_at: "2026-10-20T12:05:00Z" }], [2, { state: "success", created_at: "2026-10-20T11:03:00Z" }],
        [1, { state: "inactive", created_at: "2026-10-20T11:03:00Z" }]]));
    expect(out).toEqual({ environment: "Production", host: "vercel", live: { sha: sha("b"), at: "2026-10-20T11:03:00Z" },
      latest: { sha: sha("c"), state: "failure", at: "2026-10-20T12:05:00Z" } });
  });

  it("ignores preview deploys and says none when no production deploy succeeded", () => {
    const out = summarizeDeploys([d(5, "e", "2026-10-20T12:00:00Z", { environment: "Preview", production_environment: false }),
      d(4, "d", "2026-10-20T11:00:00Z")], new Map([[4, { state: "in_progress", created_at: "2026-10-20T11:01:00Z" }]]));
    expect(out).toEqual({ environment: "Production", host: "vercel", live: null, latest: { sha: sha("d"), state: "in_progress", at: "2026-10-20T11:01:00Z" } });
    expect(summarizeDeploys([], new Map())).toBeNull();
  });
});

describe("readProductionDeploy", () => {
  const fetchMock = vi.fn();
  afterEach(() => { vi.unstubAllGlobals(); fetchMock.mockReset(); });
  const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

  it("reads the live commit and how far the default branch is ahead of it", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes("/deployments?")) return json([d(2, "b", "2026-10-20T11:00:00Z")]);
      if (url.includes("/deployments/2/statuses")) return json([{ state: "success", created_at: "2026-10-20T11:03:00Z" }]);
      if (url.includes("/compare/")) return json({ status: "ahead", ahead_by: 3 });
      return json({}, 404);
    });
    const out = await readProductionDeploy("tok", "acme/app", sha("f"));
    expect(out).toEqual({ state: "read", environment: "Production", host: "vercel", headSha: sha("f"),
      live: { sha: sha("b"), at: "2026-10-20T11:03:00Z" }, latest: { sha: sha("b"), state: "success", at: "2026-10-20T11:03:00Z" }, behindBy: 3 });
    expect(fetchMock.mock.calls.find(([u]) => String(u).includes("/compare/"))?.[0]).toContain(`/compare/${sha("b")}...${sha("f")}`);
    expect(productionDeploySchema.safeParse(out).success).toBe(true);
  });

  it("says behind 0 when live is the head, and unknown when history diverged", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockImplementation(async (url: string) => url.includes("/deployments?") ? json([d(2, "f", "2026-10-20T11:00:00Z")])
      : json([{ state: "success", created_at: "2026-10-20T11:03:00Z" }]));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toMatchObject({ behindBy: 0 });
    fetchMock.mockImplementation(async (url: string) => url.includes("/deployments?") ? json([d(2, "b", "2026-10-20T11:00:00Z")])
      : url.includes("/compare/") ? json({ status: "diverged", ahead_by: 2, behind_by: 1 }) : json([{ state: "success", created_at: "x" }]));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toMatchObject({ behindBy: null });
  });

  it("is none when the host reports no production deploys to GitHub", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(json([]));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toEqual({ state: "none" });
  });

  it("is unreadable, never current, without the deployments permission or when GitHub fails", async () => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(json({ message: "Resource not accessible by integration" }, 403));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toEqual({ state: "unreadable",
      why: "ShipLock's GitHub App has not been granted read access to deployments." });
    fetchMock.mockRejectedValue(new Error("ETIMEDOUT"));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toMatchObject({ state: "unreadable" });
    fetchMock.mockImplementation(async (url: string) => url.includes("/deployments?") ? json([d(2, "b", "2026-10-20T11:00:00Z")]) : json({}, 500));
    expect(await readProductionDeploy("tok", "acme/app", sha("f"))).toMatchObject({ state: "unreadable" });
  });
});
