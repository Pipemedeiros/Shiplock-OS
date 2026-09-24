import { afterEach, describe, expect, it, vi } from "vitest";
import { capturePreview, createBranch, findOpenPullRequestForBranch, openPullRequest, putFile } from "./github";

// Q13 / Step 8: in preview mode no GitHub write leaves ShipLock. Writes are
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
