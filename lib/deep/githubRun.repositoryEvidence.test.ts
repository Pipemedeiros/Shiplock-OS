import { beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  listTree: vi.fn(),
  getFile: vi.fn(),
  queryOsv: vi.fn(),
  listRecentCommitPatches: vi.fn(),
}));
const visibilityCheck = vi.hoisted(() => vi.fn());
vi.mock("./github", () => api);
vi.mock("./repoVisibility", () => ({ checkRepoVisibility: visibilityCheck }));

import { collectRepositorySource } from "./githubRun";
import type { Repo } from "./github";

const repos: Repo[] = ["acme/one", "acme/two"].map((fullName, index) => ({
  id: String(101 + index),
  fullName,
  defaultBranch: "main",
  isPrivate: true,
  visibility: "private",
}));
const repositoryIds = [
  "11111111-1111-4111-8111-111111111111",
  "22222222-2222-4222-8222-222222222222",
];
const routePath = "app/api/data/route.ts";

async function collect(index = 0) {
  return collectRepositorySource("mock-token", repos[index], repositoryIds[index], 42);
}

beforeEach(() => {
  vi.clearAllMocks();
  api.listTree.mockResolvedValue([
    { path: routePath, size: 100 },
    { path: "package.json", size: 100 },
  ]);
  api.getFile.mockImplementation(async (_token, repository, path) => {
    const first = repository === "acme/one";
    return path === "package.json"
      ? JSON.stringify({ dependencies: { shared: first ? "1.0.0" : "2.0.0" } })
      : `export async function GET(){return supabase.from("${first ? "invoices" : "projects"}").select("*")}`;
  });
  api.queryOsv.mockResolvedValue([]);
  api.listRecentCommitPatches.mockResolvedValue([]);
  visibilityCheck.mockReturnValue([]);
});

describe("repository source collection", () => {
  it("keeps identical paths and different dependency versions in separate repository snapshots", async () => {
    const first = await collect(0);
    const second = await collect(1);

    expect(first.snapshot).toMatchObject({
      repositoryId: repositoryIds[0],
      providerRepositoryId: "101",
      repositoryFullName: "acme/one",
      installationId: "42",
      ref: "main",
      completeness: "partial",
      hasEntryPoints: true,
      liveFiles: [routePath],
      dependencies: [{ name: "shared", version: "1.0.0" }],
      filesRead: 2,
      filesAttempted: 2,
    });
    expect(second.snapshot.dependencies).toEqual([{ name: "shared", version: "2.0.0" }]);
    expect(first.snapshot.routes[0].tables).toEqual(["invoices"]);
    expect(second.snapshot.routes[0].tables).toEqual(["projects"]);
    expect(Number.isFinite(Date.parse(first.snapshot.recordedAt))).toBe(true);
    expect(JSON.stringify(first)).not.toContain("mock-token");
    expect(JSON.stringify(first)).not.toContain("export async");
  });

  it("returns no empty snapshot when the repository tree cannot be read", async () => {
    api.listTree.mockRejectedValue(new Error("unreadable"));
    await expect(collect()).rejects.toThrow("unreadable");
  });

  it("does not publish already-mutated local sinks after a late scanner failure", async () => {
    visibilityCheck.mockImplementation(() => {
      throw new Error("late scanner failure");
    });
    await expect(collect()).rejects.toThrow("late scanner failure");
  });

  it("preserves the 60-file budget and partial status", async () => {
    api.listTree.mockResolvedValue(
      Array.from({ length: 65 }, (_, index) => ({ path: `lib/file${index}.ts`, size: 100 })),
    );
    const result = await collect();
    expect(api.getFile).toHaveBeenCalledTimes(60);
    expect(result.snapshot).toMatchObject({
      filesAttempted: 60,
      filesRead: 60,
      completeness: "partial",
    });
  });

  it("records attempted and successful file counts without calling a partial read complete", async () => {
    api.getFile.mockResolvedValue(null);
    const { snapshot } = await collect();
    expect(snapshot).toMatchObject({
      filesAttempted: 2,
      filesRead: 0,
      completeness: "partial",
      routes: [],
      hasEntryPoints: false,
    });
  });
});
