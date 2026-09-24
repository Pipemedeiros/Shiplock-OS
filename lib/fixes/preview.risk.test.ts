import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Q13-F parity for the Risks-board lane: a new fix-request file on a new
// branch. The preview must equal what the click writes, and must not reach
// the lane's post-PR finding update.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(), getInstallationToken: async () => "tok",
}));
const finding = vi.hoisted(() => ({ rowId: "row-1", id: "authz:orders", title: "Orders readable by anyone", repository: "acme/app",
  fixKind: "pr", fixPrUrl: null, fixPrNumber: null, severity: "CRITICAL", consequence: "Anyone can read orders.",
  entry: "/api/orders", file: "app/api/orders/route.ts", attackClass: "missing_authorization", confidence: "inferred",
  blastRadius: "orders", claims: [], detectedAt: "2026-09-20T00:00:00Z" }));
vi.mock("@/lib/agent/dashboardData", () => ({ getOpenFindings: async () => [finding] }));
const updates = vi.hoisted(() => vi.fn());
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const data = table === "user_profiles" ? { github_installation_id: 42 } : { full_name: "acme/app", default_branch: "main" };
  Object.assign(q, { select: () => q, eq: () => q, single: async () => ({ data, error: null }), maybeSingle: async () => ({ data, error: null }),
    update: (row: unknown) => { updates(table, row); return q; }, then: (res: (v: unknown) => unknown) => res({ error: null }) });
  return q;
} }) }));

import { openRiskFixPr } from "./riskFixPr";
import { previewRepair } from "./preview";

const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
let created = false;
beforeEach(() => {
  writes.length = 0; created = false; updates.mockClear();
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      if (url.endsWith("/git/refs")) created = true;
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/11" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return created ? new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("Risks-board fix preview parity (Q13-F)", () => {
  it("shows the file and PR the click opens, writes nothing, and skips the post-PR update", async () => {
    const preview = await previewRepair("u1", { action: "risk-fix-pr", repositoryId: "r1", findingId: "authz:orders" });
    expect(writes).toEqual([]);
    expect(updates).not.toHaveBeenCalled();
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    await openRiskFixPr("u1", "authz:orders", "r1");
    const puts = writes.filter((w) => w.method === "PUT");
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    expect(preview.files).toEqual(puts.map((put) => ({
      path: decodeURIComponent(put.url.split("/contents/")[1]), change: "add", before: null,
      after: Buffer.from(String(put.body.content), "base64").toString("utf8") })));
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
    expect(updates).toHaveBeenCalledTimes(1);
  });
});
