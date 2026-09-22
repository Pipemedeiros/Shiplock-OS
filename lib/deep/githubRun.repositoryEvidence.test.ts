import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  getInstallationToken: vi.fn(), listRepos: vi.fn(), listTree: vi.fn(), getFile: vi.fn(),
  queryOsv: vi.fn(), listRecentCommitPatches: vi.fn(),
}));
const saveFacts = vi.hoisted(() => vi.fn());
const insert = vi.hoisted(() => vi.fn());
const selected = vi.hoisted(() => vi.fn());
const visibilityCheck = vi.hoisted(() => vi.fn());
vi.mock("./github", () => api);
vi.mock("@/lib/graph/graphRun", () => ({ saveFacts }));
vi.mock("./repoVisibility", () => ({ checkRepoVisibility: visibilityCheck }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({ from: (table: string) => ({
    select: () => table === "repositories"
      ? ({ eq: () => ({ eq: () => ({ limit: selected }) }) })
      : ({ eq: () => ({ eq: () => ({ is: async () => ({ data: [], error: null }) }) }) }),
    insert,
  }) }),
}));

import { runGithubScan } from "./githubRun";
const repos = ["acme/one", "acme/two"].map((fullName) => ({
  id: null, fullName, defaultBranch: "main", isPrivate: true, visibility: "private",
}));
const routePath = "app/api/data/route.ts";

beforeEach(() => {
  vi.clearAllMocks();
  api.getInstallationToken.mockResolvedValue("mock-token");
  api.listRepos.mockResolvedValue(repos);
  api.listTree.mockResolvedValue([{ path: routePath, size: 100 }, { path: "package.json", size: 100 }]);
  api.getFile.mockImplementation(async (_token, repository, path) => {
    const first = repository === "acme/one";
    return path === "package.json"
      ? JSON.stringify({ dependencies: { shared: first ? "1.0.0" : "2.0.0" } })
      : `export async function GET(){return supabase.from("${first ? "invoices" : "projects"}").select("*")}`;
  });
  api.queryOsv.mockResolvedValue([]);
  api.listRecentCommitPatches.mockResolvedValue([]);
  saveFacts.mockResolvedValue(undefined);
  selected.mockResolvedValue({data:repos.map((repo) => ({full_name:repo.fullName})),error:null});
  insert.mockResolvedValue({ error: null });
  visibilityCheck.mockReturnValue([]);
});

describe("Step 2C-2: repository source provenance", () => {
  it("keeps identical route/file paths and different dependency versions in separate repository snapshots", async () => {
    await runGithubScan("u", 42);
    const [user, collector, facts, metadata] = saveFacts.mock.calls[0];
    expect([user, collector]).toEqual(["u", "source"]);
    expect(facts.repositories).toHaveLength(2);
    expect(facts.repositories.map((snapshot: { repositoryFullName: string }) => snapshot.repositoryFullName))
      .toEqual(["acme/one", "acme/two"]);
    expect(facts.repositories[0]).toMatchObject({
      installationId: "42", ref: "main", completeness: "partial", hasEntryPoints: true,
      liveFiles: [routePath], dependencies: [{ name: "shared", version: "1.0.0" }],
      filesRead: 2, filesAttempted: 2,
    });
    expect(facts.repositories[1].dependencies).toEqual([{ name: "shared", version: "2.0.0" }]);
    expect(facts.repositories[0].routes[0].tables).toEqual(["invoices"]);
    expect(facts.repositories[1].routes[0].tables).toEqual(["projects"]);
    expect(facts.repositories.every((snapshot: { recordedAt: string }) => Number.isFinite(Date.parse(snapshot.recordedAt)))).toBe(true);
    expect(metadata.completeness).toBe("partial");
    // Existing consumers retain exactly the established flat representation.
    expect(facts.routes).toEqual(facts.repositories.flatMap((snapshot: { routes: unknown[] }) => snapshot.routes));
    expect(facts.dependencies).toEqual([{ name: "shared", version: "2.0.0" }]);
    expect(JSON.stringify(facts)).not.toContain("mock-token");
    expect(JSON.stringify(facts)).not.toContain("export async");
  });

  it("never turns a failed repository tree read into an empty snapshot", async () => {
    api.listTree.mockImplementation(async (_token, repository) => {
      if (repository === "acme/two") throw new Error("unreadable");
      return [{ path: routePath, size: 100 }];
    });
    await runGithubScan("u", "installation");
    const facts = saveFacts.mock.calls[0][2];
    expect(facts.repositories).toHaveLength(1);
    expect(facts.repositories[0].repositoryFullName).toBe("acme/one");
    expect(facts.routes).toEqual(facts.repositories[0].routes);
  });

  it("preserves prior stored evidence when every repository fails", async () => {
    api.listTree.mockRejectedValue(new Error("unreadable"));
    await runGithubScan("u", 42);
    expect(saveFacts).not.toHaveBeenCalled();
  });

  it("does not leak a failed repository's already-mutated sinks into either representation", async () => {
    visibilityCheck.mockImplementation((repo) => {
      if (repo.fullName === "acme/two") throw new Error("late scanner failure");
      return [];
    });
    await runGithubScan("u", 42);
    const facts = saveFacts.mock.calls[0][2];
    expect(facts.repositories).toHaveLength(1);
    expect(facts.routes).toEqual(facts.repositories[0].routes);
    expect(facts.dependencies).toEqual([{ name: "shared", version: "1.0.0" }]);
  });

  it("preserves the existing 60-file budget and partial status", async () => {
    api.listRepos.mockResolvedValue([repos[0]]);
    api.listTree.mockResolvedValue(Array.from({ length: 65 }, (_, index) => ({ path: `lib/file${index}.ts`, size: 100 })));
    await runGithubScan("u", 42);
    expect(api.getFile).toHaveBeenCalledTimes(60);
    expect(saveFacts.mock.calls[0][2].repositories[0]).toMatchObject({ filesAttempted: 60, filesRead: 60, completeness: "partial" });
  });

  it("never reads an installation repository the customer did not select", async () => {
    selected.mockResolvedValue({data:[{full_name:"acme/one"}],error:null});
    await runGithubScan("u",42);
    expect(api.listTree).toHaveBeenCalledWith("mock-token","acme/one","main");
    expect(api.listTree).not.toHaveBeenCalledWith("mock-token","acme/two","main");
    expect(saveFacts.mock.calls[0][2].repositories).toHaveLength(1);
  });

  it("records attempted and successful file counts without calling a partial read complete", async () => {
    api.listRepos.mockResolvedValue([repos[0]]);
    api.getFile.mockResolvedValue(null);
    await runGithubScan("u", 42);
    const snapshot = saveFacts.mock.calls[0][2].repositories[0];
    expect(snapshot).toMatchObject({ filesAttempted: 2, filesRead: 0, completeness: "partial", routes: [], hasEntryPoints: false });
  });
});
