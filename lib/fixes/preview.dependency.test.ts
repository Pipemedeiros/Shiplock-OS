import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Preview parity for a lane that EDITS an existing file on the branch it creates:
// the dependency bump. The preview must equal what the click writes.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(),
  getInstallationToken: async () => "tok",
  queryOsv: async () => [{ dep: { name: "lodash", version: "4.17.15" }, vulns: [{ fixedVersion: "4.17.21" }] }],
}));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const data = table === "user_profiles" ? { github_installation_id: 42 } : { full_name: "acme/app", default_branch: "main" };
  Object.assign(q, { select: () => q, eq: () => q, maybeSingle: async () => ({ data, error: null }) });
  return q;
} }) }));

import { openDependencyBumpPr } from "@/lib/deep/githubFixRun";
import { previewRepair } from "./preview";

const PKG = JSON.stringify({ name: "app", dependencies: { lodash: "^4.17.15" } }, null, 2) + "\n";
const BASE = "a".repeat(40);
const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
let branchCreated = false;
beforeEach(() => {
  writes.length = 0; branchCreated = false;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      if (url.endsWith("/git/refs")) branchCreated = true;
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/8" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: BASE } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return branchCreated ? new Response(JSON.stringify({ object: { sha: BASE } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    if (url.includes("/contents/package.json")) {
      const onBranch = url.includes("ref=shiplock");
      if (onBranch && !branchCreated) return new Response("{}", { status: 404 });
      return new Response(JSON.stringify({ sha: "p".repeat(40), encoding: "base64", content: Buffer.from(PKG).toString("base64") }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("dependency bump preview parity", () => {
  it("shows the package.json edit the click writes, and writes nothing itself", async () => {
    const preview = await previewRepair("u1", { action: "dependency-bump-pr", repositoryId: "r1" });
    expect(writes).toEqual([]);
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    await openDependencyBumpPr("u1", "r1");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    expect(preview.files).toEqual([{ path: "package.json", change: "edit", before: PKG,
      after: Buffer.from(String(put.body.content), "base64").toString("utf8") }]);
    expect(preview.files[0].after).toContain("^4.17.21");
    expect({ title: preview.title, branch: preview.branch, base: preview.base }).toEqual({ title: pr.body.title, branch: pr.body.head, base: pr.body.base });
  });
});
