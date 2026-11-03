import { afterEach, describe, expect, it, vi } from "vitest";
import { capturePreview, createBranch, findOpenPullRequestForBranch, openPullRequest, putFile } from "./github";

// In preview mode no GitHub write leaves ShipLock. Writes are
// recorded, and the lane stops at "open PR" so nothing after it runs.
afterEach(() => vi.unstubAllGlobals());

describe("capturePreview", () => {
  it("records branch, file and PR writes without sending any", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    let after = false;
    const capture = await capturePreview(async () => {
      await createBranch("tok", "acme/app", "shiplock/x", "a".repeat(40));
      await putFile("tok", "acme/app", "lib/x.ts", "shiplock/x", "export const x = 1;\n", undefined, "msg");
      await openPullRequest("tok", "acme/app", "shiplock/x", "main", "Title", "Body");
      after = true;
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(after).toBe(false);
    expect(capture).toEqual({ status: "planned", token: "tok", repository: "acme/app", branch: "shiplock/x", base: "main",
      title: "Title", body: "Body", files: [{ path: "lib/x.ts", content: "export const x = 1;\n" }] });
  });

  it("stops at an already open PR", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify([{ html_url: "https://github.com/acme/app/pull/4" }]), { status: 200 })));
    const capture = await capturePreview(async () => { await findOpenPullRequestForBranch("tok", "acme/app", "shiplock/x"); throw new Error("unreachable"); });
    expect(capture).toEqual({ status: "already_open", url: "https://github.com/acme/app/pull/4" });
  });

  it("returns the lane's own result when it stops before writing", async () => {
    vi.stubGlobal("fetch", vi.fn());
    expect(await capturePreview(async () => ({ status: "failed", code: "no_changes" }))).toEqual({ status: "not_planned", result: { status: "failed", code: "no_changes" } });
  });

  it("outside preview mode writes still go to GitHub", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ html_url: "https://github.com/acme/app/pull/5" }), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await openPullRequest("tok", "acme/app", "h", "main", "t", "b")).toBe("https://github.com/acme/app/pull/5");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("capturePreview reads on the branch it pretended to create", () => {
  it("reads the new branch as its base commit, and sees files the lane already wrote", async () => {
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method && init.method !== "GET") throw new Error("write sent");
      urls.push(url);
      if (url.includes("/contents/package.json")) {
        return new Response(JSON.stringify({ sha: "f".repeat(40), encoding: "base64", content: Buffer.from("{}").toString("base64") }), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    }));
    const { getBranchSha, getFile, getFileSha } = await import("./github");
    const seen: unknown[] = [];
    await capturePreview(async () => {
      await createBranch("tok", "acme/app", "shiplock/new", "a".repeat(40));
      seen.push(await getBranchSha("tok", "acme/app", "shiplock/new"));
      seen.push(await getFileSha("tok", "acme/app", "package.json", "shiplock/new"));
      await putFile("tok", "acme/app", "lib/x.ts", "shiplock/new", "written", undefined, "m");
      seen.push(await getFile("tok", "acme/app", "lib/x.ts", "shiplock/new"));
      return null;
    });
    expect(seen).toEqual(["a".repeat(40), "f".repeat(40), "written"]);
    expect(urls.every((u) => !u.includes("ref=shiplock%2Fnew"))).toBe(true);
    expect(urls.some((u) => u.includes(`ref=${"a".repeat(40)}`))).toBe(true);
  });
});

// A5 (Felipe 2026-10-07): ShipLock PRs are labeled "ShipLock", so they read as
// ShipLock's in the customer's PR list and CI. Best effort: the label never
// fails the PR, and preview mode stops before it (the PR write never happens).
describe("ShipLock label", () => {
  it("labels the PR it opens", async () => {
    const fetchMock = vi.fn(async (url: string) => new Response(JSON.stringify(String(url).endsWith("/pulls")
      ? { html_url: "https://github.com/acme/app/pull/7", number: 7 } : [{ name: "ShipLock" }]), { status: 201 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await openPullRequest("tok", "acme/app", "h", "main", "t", "b")).toBe("https://github.com/acme/app/pull/7");
    const [url, init] = fetchMock.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/repos\/acme\/app\/issues\/7\/labels$/);
    expect(JSON.parse(String(init.body))).toEqual({ labels: ["ShipLock"] });
  });
  it("still returns the PR when labeling is refused", async () => {
    const fetchMock = vi.fn(async (url: string) => String(url).endsWith("/pulls")
      ? new Response(JSON.stringify({ html_url: "https://github.com/acme/app/pull/8", number: 8 }), { status: 201 })
      : new Response("{}", { status: 403 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await openPullRequest("tok", "acme/app", "h", "main", "t", "b")).toBe("https://github.com/acme/app/pull/8");
  });
});
