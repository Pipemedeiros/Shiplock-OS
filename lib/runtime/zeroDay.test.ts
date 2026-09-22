import { beforeEach, expect, it, vi } from "vitest";

const queryOsv = vi.hoisted(() => vi.fn());
vi.mock("@/lib/deep/github", () => ({ queryOsv }));

import { collectDependencyFindings, stripRepoPrefix } from "./zeroDay";

const inventory = {
  repositoryId: "11111111-1111-4111-8111-111111111111",
  repositoryFullName: "acme/one",
  sourceRevision: "2026-09-22T00:00:00.000Z",
  dependencies: [{ name: "left-pad", version: "1.0.0" }],
  completeness: "partial" as const,
};

beforeEach(() => {
  vi.clearAllMocks();
  queryOsv.mockResolvedValue([{ dep: inventory.dependencies[0], vulns: [{
    id: "GHSA-x",
    cveId: "CVE-2026-1",
    summary: "RCE",
    severity: "CRITICAL",
    fixedVersion: "1.0.1",
  }] }]);
});

it("collects and namespaces current advisories without persisting", async () => {
  const findings = await collectDependencyFindings(inventory);
  expect(queryOsv).toHaveBeenCalledWith(inventory.dependencies);
  expect(findings[0]).toMatchObject({
    id: "acme/one::github:dep:left-pad:GHSA-x",
    severity: "CRITICAL",
  });
  expect(findings[0].consequence).toContain("Source coverage is partial");
});

it("does no provider work for an observed empty inventory", async () => {
  await expect(collectDependencyFindings({ ...inventory, dependencies: [] })).resolves.toEqual([]);
  expect(queryOsv).not.toHaveBeenCalled();
});

it("propagates an advisory outage so the durable job can retry", async () => {
  queryOsv.mockRejectedValue(new Error("outage"));
  await expect(collectDependencyFindings(inventory)).rejects.toThrow("outage");
});

it("retains the historical prefix helper", () => {
  expect(stripRepoPrefix("acme/app::github:dep:a::b")).toBe("github:dep:a::b");
  expect(stripRepoPrefix("github:dep:a")).toBe("github:dep:a");
});
