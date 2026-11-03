import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Preview parity for fix before merge: a new branch cut from the PR's own head,
// with the PR targeting that head branch, never the default branch.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(), getInstallationToken: async () => "tok",
}));
const REVIEW = "77777777-7777-4777-8777-777777777777";
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const data = table === "user_profiles" ? { github_installation_id: 42 } : {
    pull_request_number: 7, head_ref: "feature/orders", same_repository: true, repositories: { full_name: "acme/app" },
    findings: [{ id: "diff:orders", severity: "CRITICAL", title: "Orders route skips auth", detail: "No session check.",
      file: "app/api/orders/route.ts", evidence: "export async function GET() {" }] };
  Object.assign(q, { select: () => q, eq: () => q, maybeSingle: async () => ({ data, error: null }) });
  return q;
} }) }));

import { openPullRequestFixPr } from "./pullRequestFixPr";
import { previewRepair } from "./preview";

const HEAD = "b".repeat(40);
const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
let created = false;
beforeEach(() => {
  writes.length = 0; created = false;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      if (url.endsWith("/git/refs")) created = true;
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/13" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/feature%2Forders")) return new Response(JSON.stringify({ object: { sha: HEAD } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return created ? new Response(JSON.stringify({ object: { sha: HEAD } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("fix-before-merge preview parity", () => {
  it("shows the fix request the click opens into the PR's branch, and writes nothing itself", async () => {
    const preview = await previewRepair("u1", { action: "pr-fix-pr", repositoryId: "r1", reviewId: REVIEW, findingId: "diff:orders" });
    expect(writes).toEqual([]);
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    await openPullRequestFixPr("u1", REVIEW, "diff:orders", "r1");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    const ref = writes.find((w) => w.url.endsWith("/git/refs"))!;
    expect(ref.body.sha).toBe(HEAD);
    expect(preview.base).toBe("feature/orders");
    expect(preview.files).toEqual([{ path: decodeURIComponent(put.url.split("/contents/")[1]), change: "add", before: null,
      after: Buffer.from(String(put.body.content), "base64").toString("utf8") }]);
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
  });
});
