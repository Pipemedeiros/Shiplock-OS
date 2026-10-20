import { afterEach, expect, it, vi } from "vitest";
import { createCheckRun, findOpenPullRequestForBranch, listPullRequestFiles } from "./github";

afterEach(() => vi.unstubAllGlobals());

it("updates the existing check with the same external id on retry", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({check_runs:[{id:91,external_id:"stable"}]}),{status:200}))
    .mockResolvedValueOnce(new Response(JSON.stringify({id:91}),{status:200}));
  vi.stubGlobal("fetch",fetchMock);
  await createCheckRun("token","acme/app","a".repeat(40),"success","ok","summary","stable");
  expect(fetchMock.mock.calls[1][0]).toContain("/check-runs/91");
  expect(fetchMock.mock.calls[1][1]).toMatchObject({method:"PATCH"});
});

it("creates a check when no matching retry receipt exists", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({check_runs:[]}),{status:200}))
    .mockResolvedValueOnce(new Response(JSON.stringify({id:92}),{status:201}));
  vi.stubGlobal("fetch",fetchMock);
  await createCheckRun("token","acme/app","a".repeat(40),"neutral","partial","summary","stable");
  expect(fetchMock.mock.calls[1][0]).toMatch(/\/check-runs$/);
  expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toMatchObject({head_sha:"a".repeat(40),external_id:"stable"});
});

it("marks deleted, bounded, paginated, and unreadable files as partial", async () => {
  const response = new Response(JSON.stringify([
    {filename:"one.ts",status:"modified"}, {filename:"gone.ts",status:"removed"}, {filename:"two.ts",status:"added"},
  ]),{status:200,headers:{link:'<https://api.github.com/next>; rel="next"'}});
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(response)
    .mockResolvedValueOnce(new Response(JSON.stringify({encoding:"base64",content:Buffer.from("one").toString("base64")}),{status:200}));
  vi.stubGlobal("fetch",fetchMock);
  const result = await listPullRequestFiles("token","acme/app",7,"a".repeat(40),1);
  expect(result.files).toEqual([{path:"one.ts",content:"one"}]);
  expect(result.complete).toBe(false);
  expect(result.coverage).toContain("deleted file");
  expect(result.coverage).toContain("review budget");
});

// Production 2026-10-20: a probe PR with an empty commit got "All 0 changed
// files were readable." on its check run.
it("says a pull request changes no files instead of counting zero", async () => {
  vi.stubGlobal("fetch",vi.fn().mockResolvedValueOnce(new Response("[]",{status:200})));
  const result = await listPullRequestFiles("token","acme/app",7,"a".repeat(40));
  expect(result.complete).toBe(true);
  expect(result.coverage).toBe("This pull request changes no files.");
});

it("recovers an already-open PR by deterministic head branch", async () => {
  const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify([{html_url:"https://github.com/acme/app/pull/7"}]),{status:200}));
  vi.stubGlobal("fetch",fetchMock);
  await expect(findOpenPullRequestForBranch("token","acme/app","shiplock/fix-abc")).resolves.toBe("https://github.com/acme/app/pull/7");
  expect(fetchMock.mock.calls[0][0]).toContain("head=acme%3Ashiplock%2Ffix-abc");
});

it("lists the customer's check runs for a pull request's head, without ShipLock's own", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ head: { sha: "b".repeat(40) } }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ check_runs: [
      { name: "ShipLock", status: "completed", conclusion: "failure" },
      { name: "test", status: "completed", conclusion: "success" },
    ] }), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  const { listPullRequestCheckRuns } = await import("./github");
  expect(await listPullRequestCheckRuns("token", "acme/app", 9)).toEqual([{ status: "completed", conclusion: "success" }]);
  expect(fetchMock.mock.calls[1][0]).toContain(`/commits/${"b".repeat(40)}/check-runs?filter=latest&per_page=100`);
  expect(fetchMock.mock.calls.every((call) => !call[1]?.method || call[1].method === "GET")).toBe(true);
});
