import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Preview parity for your AI's fix: an edit of an existing file on a new branch.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(), getInstallationToken: async () => "tok",
}));
vi.mock("@/lib/intelligence/tasks", () => ({ mechanicalEdit: () => true }));
const BEFORE = "export const a = 1;\n";
const AFTER = "export const a = 2;\n";
const TASK = "88888888-8888-4888-8888-888888888888";
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const data = table === "user_profiles" ? { github_installation_id: 42 } : {
    id: TASK, repository_id: "33333333-3333-4333-8333-333333333333", status: "proposal_received", idempotency_key: "deep:x", host: "codex",
    result: { summary: "Tighten a", edits: [{ path: "lib/a.ts", baseHash: createHash("sha256").update(BEFORE).digest("hex"), content: AFTER }] },
    repositories: { full_name: "acme/app", default_branch: "main", selected: true } };
  Object.assign(q, { select: () => q, eq: () => q, maybeSingle: async () => ({ data, error: null }) });
  return q;
} }) }));

import { openAiFixPr } from "./aiFixPr";
import { previewRepair } from "./preview";

const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
let created = false;
beforeEach(() => {
  writes.length = 0; created = false;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      if (url.endsWith("/git/refs")) created = true;
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/9" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return created ? new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    if (url.includes("/contents/lib/a.ts")) {
      if (url.includes("ref=shiplock") && !created) return new Response("{}", { status: 404 });
      return new Response(JSON.stringify({ sha: "s".repeat(40), encoding: "base64", content: Buffer.from(BEFORE).toString("base64") }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("AI fix preview parity", () => {
  it("shows the edit the click writes, and writes nothing itself", async () => {
    const preview = await previewRepair("u1", { action: "ai-fix-pr", repositoryId: "33333333-3333-4333-8333-333333333333", taskId: TASK });
    expect(writes).toEqual([]);
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    await openAiFixPr("u1", TASK, "33333333-3333-4333-8333-333333333333");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    expect(preview.files).toEqual([{ path: "lib/a.ts", change: "edit", before: BEFORE, after: Buffer.from(String(put.body.content), "base64").toString("utf8") }]);
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
  });
});
