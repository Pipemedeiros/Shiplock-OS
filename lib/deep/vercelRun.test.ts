import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ProviderResult } from "@/lib/monitoring/registry";

// The audit hands one result to the monitor worker's fenced commit (3F-C2c).
// Insert-if-new and merge semantics are proven in the SQL suite; these tests
// pin what the runner sends and withholds.
const decryptMock = vi.fn();
const listProjectsMock = vi.fn();
const listProjectEnvMock = vi.fn();
const syncVercelRepositoryLinksMock = vi.fn();
const commitMock = vi.fn();

vi.mock("./providerRepositoryMap", () => ({
  syncVercelRepositoryLinks: syncVercelRepositoryLinksMock,
}));
vi.mock("@/lib/crypto", () => ({ decrypt: decryptMock }));
vi.mock("./vercel", () => ({
  listProjects: listProjectsMock,
  listProjectEnv: listProjectEnvMock,
}));

const { runVercelEnvAudit } = await import("./vercelRun");

const EPOCH = "1".repeat(64);
const run = (options: { signal?: AbortSignal } = {}, epoch = EPOCH) =>
  runVercelEnvAudit("user-1", "cipher", epoch, null, { commit: commitMock, ...options });
const sent = () => commitMock.mock.calls[0][0] as ProviderResult;
const secretEnv = [{ key: "NEXT_PUBLIC_SECRET_TOKEN", value: "a-long-enough-secret-value-here" }];

beforeEach(() => {
  decryptMock.mockReset().mockReturnValue("plaintext-access-token");
  listProjectsMock.mockReset();
  listProjectEnvMock.mockReset();
  syncVercelRepositoryLinksMock.mockReset().mockResolvedValue(new Map());
  commitMock.mockReset().mockImplementation(async (result: ProviderResult) => result.findings);
});

describe("runVercelEnvAudit", () => {
  it("decrypts the stored token before calling the Vercel API", async () => {
    listProjectsMock.mockResolvedValue([]);
    await run();
    expect(decryptMock).toHaveBeenCalledWith("cipher");
    expect(listProjectsMock).toHaveBeenCalledWith("plaintext-access-token", null, undefined);
  });

  it("sends every project's env findings to the fenced commit without retiring", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "site-one" }]);
    listProjectEnvMock.mockResolvedValue(secretEnv);
    const result = await run();
    expect(sent()).toMatchObject({ transport: "vercel", identity: EPOCH, retire: false });
    expect(sent().findings.map((finding) => finding.id)).toEqual(["vercel:site-one:NEXT_PUBLIC_SECRET_TOKEN:client_exposed_secret"]);
    expect(result).toMatchObject({ total: 1, newCount: 1 });
    expect(result.newFindings).toEqual(sent().findings);
  });

  it("reports only what the commit newly inserted", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "site-one" }]);
    listProjectEnvMock.mockResolvedValue(secretEnv);
    commitMock.mockResolvedValue([]);
    const result = await run();
    expect(result).toMatchObject({ total: 1, newCount: 0, newFindings: [] });
  });

  it("skips a project whose env read fails without failing the whole pass", async () => {
    listProjectsMock.mockResolvedValue([
      { id: "p1", name: "broken-project" },
      { id: "p2", name: "healthy-project" },
    ]);
    listProjectEnvMock.mockImplementation(async (_token: string, projectId: string) => {
      if (projectId === "p1") throw new Error("Vercel env read HTTP 404");
      return secretEnv;
    });
    const result = await run();
    expect(result.total).toBe(1);
    expect(result.findings[0].id).toContain("healthy-project");
  });

  it("fails closed when projects exist but none of their environments are readable", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "unreadable" }]);
    listProjectEnvMock.mockRejectedValue(new Error("Vercel env read HTTP 503"));
    await expect(run()).rejects.toThrow("No Vercel project environment was readable");
    expect(commitMock).not.toHaveBeenCalled();
  });

  it("caps processing at the first 20 projects", async () => {
    listProjectsMock.mockResolvedValue(Array.from({ length: 25 }, (_, i) => ({ id: `p${i}`, name: `proj-${i}` })));
    listProjectEnvMock.mockResolvedValue([]);
    await run();
    expect(listProjectEnvMock).toHaveBeenCalledTimes(20);
  });

  it("sends project identity and the epoch without environment values", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "one" }, { id: "p2", name: "two" }]);
    listProjectEnvMock.mockResolvedValue([{ key: "API_KEY", target: ["production"], value: "private-test-value" }]);
    await run();
    expect(sent().facts).toEqual({
      envVars: [
        { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p1", connectionFingerprint: EPOCH },
        { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p2", connectionFingerprint: EPOCH },
      ],
      providersRead: ["vercel"],
    });
    expect(JSON.stringify(commitMock.mock.calls)).not.toContain("private-test-value");
  });

  it("adds repository identity only for a persisted provider link, stamped with the epoch", async () => {
    listProjectsMock.mockResolvedValue([
      { id: "p1", name: "one", gitRepository: { type: "github", fullName: "acme/app", repoId: "7" } },
      { id: "p2", name: "two" },
    ]);
    syncVercelRepositoryLinksMock.mockResolvedValue(new Map([["p1", "repo-a"]]));
    listProjectEnvMock.mockResolvedValue([{ key: "API_KEY", target: ["production"], value: "not-saved" }]);
    await run({}, "9".repeat(64));
    expect(syncVercelRepositoryLinksMock).toHaveBeenCalledWith("user-1", expect.any(Array), "9".repeat(64));
    expect((sent().facts as { envVars: unknown[] }).envVars).toEqual([
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p1", repositoryId: "repo-a", connectionFingerprint: "9".repeat(64) },
      { key: "API_KEY", target: ["production"], provider: "vercel", projectId: "p2", connectionFingerprint: "9".repeat(64) },
    ]);
  });

  it("keeps provider checks running but excludes repository attribution on mapping failure", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "one" }]);
    syncVercelRepositoryLinksMock.mockRejectedValue(new Error("mapping write failed"));
    listProjectEnvMock.mockResolvedValue([{ key: "API_KEY", target: ["production"], value: "not-saved" }]);
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await run();
      expect((sent().facts as { envVars: object[] }).envVars[0]).not.toHaveProperty("repositoryId");
    } finally { log.mockRestore(); }
  });

  it("sends no facts when no project was listed, so absence is never read as checked", async () => {
    listProjectsMock.mockResolvedValue([]);
    await run();
    expect(sent()).not.toHaveProperty("facts");
    expect(sent().findings).toEqual([]);
  });

  it("propagates a fenced rejection so the collector fails", async () => {
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "site-one" }]);
    listProjectEnvMock.mockResolvedValue(secretEnv);
    commitMock.mockRejectedValue(new Error("Provider result was not committed"));
    await expect(run()).rejects.toThrow("not committed");
  });
});

describe("3F-C2b: an aborted Vercel audit commits nothing", () => {
  it("forwards the signal and stops before mapping or the commit when aborted mid-read", async () => {
    const controller = new AbortController();
    listProjectsMock.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return [{ id: "p1", name: "site-one" }];
    });
    listProjectEnvMock.mockResolvedValue(secretEnv);
    await expect(run({ signal: controller.signal })).rejects.toThrow("collector timed out");
    expect(listProjectsMock).toHaveBeenCalledWith("plaintext-access-token", null, controller.signal);
    expect(syncVercelRepositoryLinksMock).not.toHaveBeenCalled();
    expect(commitMock).not.toHaveBeenCalled();
  });

  it("does not treat an aborted project read as one skippable project", async () => {
    const controller = new AbortController();
    listProjectsMock.mockResolvedValue([{ id: "p1", name: "one" }, { id: "p2", name: "two" }]);
    listProjectEnvMock.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      throw controller.signal.reason;
    });
    await expect(run({ signal: controller.signal })).rejects.toThrow("collector timed out");
    expect(listProjectEnvMock).toHaveBeenCalledTimes(1);
    expect(commitMock).not.toHaveBeenCalled();
  });
});
