import { beforeEach, expect, it, vi } from "vitest";

// 3F-C2d-4: source-scan dependency findings must reach a fix card; the panel
// that used to show them was never rendered.
const deep = vi.hoisted(() => vi.fn());
vi.mock("@/lib/scanHistory", () => ({ getLatestScan: vi.fn(async () => null) }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: () => {
  const chain = { select: () => chain, eq: () => chain, is: () => chain, order: () => chain, limit: deep };
  return chain;
} }) }));

import { getFixFindings } from "./findings";

beforeEach(() => {
  deep.mockResolvedValue({ data: [
    { finding_id: "github:dep:left-pad:GHSA-x", title: "Vulnerable left-pad", severity: "CRITICAL", consequence: "Upgrade.", source: "github" },
  ] });
});

it("includes source-scan dependency findings so they can be fixed with a click", async () => {
  expect((await getFixFindings("u")).map((f) => f.id)).toContain("github:dep:left-pad:GHSA-x");
});
