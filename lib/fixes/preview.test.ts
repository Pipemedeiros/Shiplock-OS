import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A preview runs the lane's real code with GitHub writes
// captured, so it shows exactly what the click would write, and writes nothing.
const lanes = vi.hoisted(() => ({ risk: vi.fn(), finding: vi.fn(), dependency: vi.fn(), pr: vi.fn(), ai: vi.fn(), rateLimit: vi.fn() }));
vi.mock("./riskFixPr", () => ({ openRiskFixPr: lanes.risk }));
vi.mock("./findingFixPr", () => ({ openFindingFixPr: lanes.finding }));
vi.mock("@/lib/deep/githubFixRun", () => ({ openDependencyBumpPr: lanes.dependency }));
vi.mock("./pullRequestFixPr", () => ({ openPullRequestFixPr: lanes.pr }));
vi.mock("./aiFixPr", () => ({ openAiFixPr: lanes.ai }));
vi.mock("./rateLimitPr", () => ({ openRateLimitPr: lanes.rateLimit }));

import { putFile, openPullRequest, createBranch, findOpenPullRequestForBranch } from "@/lib/deep/github";
import { previewRepair } from "./preview";

const fetchMock = vi.fn();
beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  // Only reads reach the network: the base branch's current file contents.
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (init?.method && init.method !== "GET") throw new Error(`write attempted: ${init.method} ${url}`);
    if (url.includes("/contents/package.json")) {
      return new Response(JSON.stringify({ encoding: "base64", content: Buffer.from("{\"a\":1}").toString("base64") }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  });
});
afterEach(() => vi.unstubAllGlobals());

const writingLane = async () => {
  await createBranch("secret-token", "acme/app", "shiplock/x", "a".repeat(40));
  await putFile("secret-token", "acme/app", "package.json", "shiplock/x", "{\"a\":2}", "sha", "m");
  await putFile("secret-token", "acme/app", "lib/new.ts", "shiplock/x", "new", undefined, "m");
  await openPullRequest("secret-token", "acme/app", "shiplock/x", "main", "Bump a", "Body text");
  throw new Error("must not continue after open");
};

describe("previewRepair", () => {
  it("shows each file as add or edit with before and after, and writes nothing", async () => {
    lanes.dependency.mockImplementation(writingLane);
    const preview = await previewRepair("u1", { action: "dependency-bump-pr", repositoryId: "r1" });
    expect(preview).toEqual({ status: "planned", lane: "Dependency update", repository: "acme/app", base: "main",
      branch: "shiplock/x", title: "Bump a", body: "Body text", tests: "not run by ShipLock",
      files: [{ path: "package.json", change: "edit", before: "{\"a\":1}", after: "{\"a\":2}" },
        { path: "lib/new.ts", change: "add", before: null, after: "new" }] });
    expect(JSON.stringify(preview)).not.toContain("secret-token");
    expect(lanes.dependency).toHaveBeenCalledWith("u1", "r1");
  });

  it("dispatches each lane with the same arguments the repair worker uses", async () => {
    for (const lane of Object.values(lanes)) lane.mockResolvedValue({ status: "failed", code: "finding_unavailable" });
    await previewRepair("u1", { action: "risk-fix-pr", repositoryId: "r1", findingId: "f" });
    await previewRepair("u1", { action: "finding-fix-pr", repositoryId: "r1", findingId: "f", editedContent: "e" });
    await previewRepair("u1", { action: "pr-fix-pr", repositoryId: "r1", findingId: "f", reviewId: "v" });
    await previewRepair("u1", { action: "ai-fix-pr", repositoryId: "r1", taskId: "t" });
    await previewRepair("u1", { action: "rate-limit-pr", repositoryId: "r1", findingId: "traffic:x" });
    expect(lanes.risk).toHaveBeenCalledWith("u1", "f", "r1");
    expect(lanes.finding).toHaveBeenCalledWith("u1", "f", "e", "r1");
    expect(lanes.pr).toHaveBeenCalledWith("u1", "v", "f", "r1");
    expect(lanes.ai).toHaveBeenCalledWith("u1", "t", "r1");
    expect(lanes.rateLimit).toHaveBeenCalledWith("u1", "traffic:x", "r1");
  });

  it("reports a lane that refuses as unavailable, and an already open PR", async () => {
    lanes.risk.mockResolvedValue({ status: "failed", code: "not_fixable" });
    expect(await previewRepair("u1", { action: "risk-fix-pr", repositoryId: "r1", findingId: "f" })).toEqual({ status: "unavailable", code: "not_fixable" });
    fetchMock.mockImplementation(async () => new Response(JSON.stringify([{ html_url: "https://github.com/acme/app/pull/3" }]), { status: 200 }));
    lanes.risk.mockImplementation(async () => { await findOpenPullRequestForBranch("t", "acme/app", "b"); return { status: "opened" }; });
    expect(await previewRepair("u1", { action: "risk-fix-pr", repositoryId: "r1", findingId: "f" })).toEqual({ status: "already_open", url: "https://github.com/acme/app/pull/3" });
  });
});
