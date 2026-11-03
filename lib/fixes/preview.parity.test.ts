import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Preview parity: the preview of a lane is exactly what the lane writes when the
// click runs it. Real rate-limit lane, real GitHub helpers, fake GitHub API.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(), getInstallationToken: async () => "tok",
}));
const rows = vi.hoisted(() => ({
  repositories: { full_name: "acme/app", default_branch: "main", selected: true },
  user_profiles: { github_installation_id: 42 },
  traffic_route_observations: [{ path: "/api/orders/1", suspicious_requests: 30 }],
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: keyof typeof rows) => {
  const q: Record<string, unknown> = {};
  const result = () => Promise.resolve({ data: rows[table], error: null });
  Object.assign(q, { select: () => q, eq: () => q, maybeSingle: result,
    then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) => result().then(res, rej) });
  return q;
} }) }));

import { openRateLimitPr } from "./rateLimitPr";
import { previewRepair } from "./preview";

const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
beforeEach(() => {
  writes.length = 0;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/7" } : {}), { status: 201 });
    }
    if (url.includes("/git/trees/")) return new Response(JSON.stringify({ tree: [{ path: "app/api/orders/[id]/route.ts", type: "blob", size: 10 }] }), { status: 200 });
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("preview parity", () => {
  it("the rate-limit preview equals what the click writes, and the preview writes nothing", async () => {
    const preview = await previewRepair("u1", { action: "rate-limit-pr", repositoryId: "r1", findingId: "traffic:app/api/orders/[id]/route.ts" });
    expect(writes).toEqual([]);
    expect(preview.status).toBe("planned");
    await openRateLimitPr("u1", "traffic:app/api/orders/[id]/route.ts", "r1");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    if (preview.status !== "planned") throw new Error("expected a plan");
    expect(preview.files).toEqual([{ path: "lib/shiplock-rate-limit.ts", change: "add", before: null,
      after: Buffer.from(String(put.body.content), "base64").toString("utf8") }]);
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
  });
});
