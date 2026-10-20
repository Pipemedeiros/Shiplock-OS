import { afterEach, expect, it, vi } from "vitest";
import { queryOsv } from "./github";

afterEach(() => vi.unstubAllGlobals());

// OSV's querybatch takes at most 1,000 queries. A lockfile read up to 1 MB holds
// about 2,000 packages; one oversized batch is refused, and the scan would then
// skip every dependency finding as "OSV unavailable".
it("asks OSV in batches of at most 1,000 and keeps each answer with its package", async () => {
  const deps = Array.from({ length: 1500 }, (_, i) => ({ name: `pkg${i}`, version: "1.0.0" }));
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith("/querybatch")) {
      const { queries } = JSON.parse(String(init?.body)) as { queries: { package: { name: string } }[] };
      if (queries.length > 1000) return new Response("too many", { status: 400 });
      return new Response(JSON.stringify({ results: queries.map((q) => (q.package.name === "pkg1200" ? { vulns: [{ id: "GHSA-x" }] } : {})) }));
    }
    return new Response(JSON.stringify({ id: "GHSA-x", aliases: [], affected: [] }));
  });
  vi.stubGlobal("fetch", fetchMock);
  const result = await queryOsv(deps);
  expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith("/querybatch"))).toHaveLength(2);
  expect(result.map((r) => r.dep.name)).toEqual(["pkg1200"]);
});
