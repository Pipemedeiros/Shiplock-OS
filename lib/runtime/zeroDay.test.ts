import { beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ inventories: vi.fn(), osv: vi.fn(), read: vi.fn(), insert: vi.fn(), update: vi.fn() }));
vi.mock("@/lib/deep/github", () => ({ queryOsv: mocks.osv }));
vi.mock("@/lib/graph/repositorySource", () => ({ loadRepositoryDependencies: mocks.inventories }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const query = { select: () => query, eq: () => query, is: mocks.read, insert: mocks.insert, update: mocks.update };
  return query;
} }) }));
import { runZeroDayCheck, stripRepoPrefix } from "./zeroDay";
const deps = [{ name: "left-pad", version: "1.0.0" }];
const inventory = { repositoryId: "r1", repositoryFullName: "acme/one", dependencies: deps, completeness: "partial" };
const vuln = { dep: deps[0], vulns: [{ id: "GHSA-x", cveId: "CVE-2026-1", summary: "RCE", severity: "CRITICAL", fixedVersion: "1.0.1" }] };
beforeEach(() => {
  vi.clearAllMocks();
  mocks.inventories.mockResolvedValue([inventory]); mocks.osv.mockResolvedValue([vuln]);
  mocks.read.mockResolvedValue({ data: [], error: null }); mocks.insert.mockResolvedValue({ error: null });
});
it("uses admitted per-repository dependencies and namespaces the result", async () => {
  expect(await runZeroDayCheck("owner")).toEqual({ total: 1, newCount: 1, resolvedCount: 0 });
  expect(mocks.osv).toHaveBeenCalledWith(deps);
  expect(mocks.insert.mock.calls[0][0][0]).toMatchObject({ user_id: "owner", repository_id: "r1", finding_id: "acme/one::github:dep:left-pad:GHSA-x" });
});
it("never suppresses repository two because repository one has the same advisory", async () => {
  mocks.inventories.mockResolvedValue([inventory, { ...inventory, repositoryId: "r2", repositoryFullName: "acme/two" }]);
  mocks.read.mockResolvedValue({ data: [{ finding_id: "acme/one::github:dep:left-pad:GHSA-x" }] });
  expect((await runZeroDayCheck("owner")).newCount).toBe(1);
  expect(mocks.insert.mock.calls[0][0][0].repository_id).toBe("r2");
});
it("deduplicates an existing advisory only in the same repository", async () => {
  mocks.read.mockResolvedValue({ data: [{ finding_id: "acme/one::github:dep:left-pad:GHSA-x" }] });
  expect((await runZeroDayCheck("owner")).newCount).toBe(0); expect(mocks.insert).not.toHaveBeenCalled();
});
it("preserves independent versions of the same package across repositories", async () => {
  mocks.inventories.mockResolvedValue([inventory, { ...inventory, repositoryId: "r2", repositoryFullName: "acme/two", dependencies: [{ name: "left-pad", version: "2.0.0" }] }]);
  await runZeroDayCheck("owner");
  expect(mocks.osv.mock.calls.map(([values]) => values[0].version)).toEqual(["1.0.0", "2.0.0"]);
});
it.each(["empty", "unread", "outage", "no-advisory"])("never archives on partial %s inventory/results", async (kind) => {
  if (kind === "empty") mocks.inventories.mockResolvedValue([{ ...inventory, dependencies: [] }]);
  if (kind === "unread") mocks.inventories.mockResolvedValue([]);
  if (kind === "outage") mocks.osv.mockRejectedValue(new Error("outage"));
  if (kind === "no-advisory") mocks.osv.mockResolvedValue([]);
  expect((await runZeroDayCheck("owner")).resolvedCount).toBe(0);
  expect(mocks.update).not.toHaveBeenCalled(); expect(mocks.insert).not.toHaveBeenCalled();
});
it("propagates a findings read failure before persistence", async () => {
  mocks.read.mockResolvedValue({ data: null, error: { message: "secret" } });
  await expect(runZeroDayCheck("owner")).rejects.toThrow("Dependency findings unavailable"); expect(mocks.insert).not.toHaveBeenCalled();
});
it("does not report successful persistence when insert fails", async () => {
  mocks.insert.mockResolvedValue({ error: { message: "secret" } });
  await expect(runZeroDayCheck("owner")).rejects.toThrow("Dependency findings could not be saved");
});
it("retains the historical prefix helper without using it for cross-repository dedup", () => {
  expect(stripRepoPrefix("acme/app::github:dep:a::b")).toBe("github:dep:a::b");
  expect(stripRepoPrefix("github:dep:a")).toBe("github:dep:a");
});
