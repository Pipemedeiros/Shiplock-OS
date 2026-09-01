import { describe, it, expect, vi, beforeEach } from "vitest";

const factsMock = vi.fn();
const osvMock = vi.fn();
const findingsSelectMock = vi.fn();
const insertMock = vi.fn();
const updateInMock = vi.fn();

vi.mock("@/lib/deep/github", () => ({ queryOsv: osvMock }));
vi.mock("@/lib/graph/graphRun", () => ({ loadGraphInput: vi.fn() }));
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "graph_facts") {
        return { select: () => ({ eq: () => ({ eq: () => ({ maybeSingle: factsMock }) }) }) };
      }
      return {
        select: () => ({ eq: () => ({ eq: () => ({ is: findingsSelectMock }) }) }),
        insert: insertMock,
        update: () => ({ eq: () => ({ eq: () => ({ is: () => ({ in: updateInMock }) }) }) }),
      };
    },
  }),
}));

const { runZeroDayCheck, stripRepoPrefix } = await import("./zeroDay");

const withDeps = { data: { facts: { dependencies: [{ name: "left-pad", version: "1.0.0" }] } } };
const vuln = {
  dep: { name: "left-pad", version: "1.0.0" },
  vulns: [{ id: "GHSA-x", cveId: "CVE-2026-1", summary: "RCE", severity: "CRITICAL", fixedVersion: "1.0.1" }],
};

describe("runZeroDayCheck", () => {
  beforeEach(() => {
    factsMock.mockReset().mockResolvedValue({ data: null });
    osvMock.mockReset().mockResolvedValue([]);
    findingsSelectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });

  // The whole point: no push required.
  it("re-checks stored dependencies without a source scan", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockResolvedValue([vuln]);
    const result = await runZeroDayCheck("u1");
    expect(osvMock).toHaveBeenCalledWith([{ name: "left-pad", version: "1.0.0" }]);
    expect(result.newCount).toBe(1);
  });

  it("explains that the code did not change — the advisory is new", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockResolvedValue([vuln]);
    await runZeroDayCheck("u1");
    expect(insertMock.mock.calls[0][0][0].consequence).toContain("Your code did not change");
  });

  it("does nothing when no source scan has ever recorded dependencies", async () => {
    const result = await runZeroDayCheck("u1");
    expect(result).toEqual({ total: 0, newCount: 0, resolvedCount: 0 });
    expect(osvMock).not.toHaveBeenCalled();
    expect(updateInMock).not.toHaveBeenCalled();
  });

  // An OSV outage must not mark every real CVE as fixed.
  it("does NOT archive anything when OSV is unreachable", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockRejectedValue(new Error("network"));
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "github:dep:left-pad:GHSA-x" }] });
    const result = await runZeroDayCheck("u1");
    expect(result.resolvedCount).toBe(0);
    expect(updateInMock).not.toHaveBeenCalled();
  });

  it("closes a finding once the dependency is upgraded", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockResolvedValue([]);
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "github:dep:left-pad:GHSA-x" }] });
    const result = await runZeroDayCheck("u1");
    expect(result.resolvedCount).toBe(1);
  });

  it("does not re-insert a CVE already open", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockResolvedValue([vuln]);
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "github:dep:left-pad:GHSA-x" }] });
    const result = await runZeroDayCheck("u1");
    expect(result.newCount).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
  });
});

// The bug found in verification: zero-day findings reuse the `github:dep:` id
// shape, and findings.ts skipped ALL such ids on the assumption they appear in
// the GitHub panel — which filters source='github'. They appeared nowhere.
describe("visibility and de-duplication", () => {
  beforeEach(() => {
    factsMock.mockReset().mockResolvedValue({ data: null });
    osvMock.mockReset().mockResolvedValue([]);
    findingsSelectMock.mockReset().mockResolvedValue({ data: [] });
    insertMock.mockReset().mockResolvedValue({ error: null });
    updateInMock.mockReset().mockResolvedValue({ error: null });
  });

  it("does not re-report a CVE already open from a pull-request scan", async () => {
    factsMock.mockResolvedValue(withDeps);
    osvMock.mockResolvedValue([vuln]);
    // Both the zero-day query and the source-scan query return the same id.
    findingsSelectMock.mockResolvedValue({ data: [{ finding_id: "github:dep:left-pad:GHSA-x" }] });
    const result = await runZeroDayCheck("u1");
    expect(result.newCount).toBe(0);
    expect(insertMock).not.toHaveBeenCalled();
  });
});

describe("the dedup that matched nothing", () => {
  it("strips the repository namespace runGithubScan adds", () => {
    expect(stripRepoPrefix("acme/app::github:dep:hono:GHSA-x")).toBe("github:dep:hono:GHSA-x");
  });

  it("leaves an id that was never namespaced alone", () => {
    expect(stripRepoPrefix("github:dep:hono:GHSA-x")).toBe("github:dep:hono:GHSA-x");
  });

  it("keeps a `::` that appears later in the id", () => {
    expect(stripRepoPrefix("acme/app::github:dep:a::b")).toBe("github:dep:a::b");
  });
});
