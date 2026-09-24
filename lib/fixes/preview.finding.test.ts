import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Q13-F parity for the fix-card lane with the customer's edited migration.
vi.mock("@/lib/deep/github", async (original) => ({
  ...await original<typeof import("@/lib/deep/github")>(), getInstallationToken: async () => "tok",
  listRepos: async () => [{ id: "1", fullName: "acme/app", defaultBranch: "main", private: true }],
}));
const finding = vi.hoisted(() => ({ id: "policy:public.orders:read:unrestricted_read", source: "policy", severity: "CRITICAL",
  title: "Orders readable by anyone", consequence: "Anyone can read orders.", fix: "Scope the policy." }));
vi.mock("./findings", () => ({ getFixFindings: async () => [finding] }));
vi.mock("@/lib/supabase", () => ({ getSupabaseAdmin: () => ({ from: (table: string) => {
  const q: Record<string, unknown> = {};
  const one = table === "user_profiles" ? { github_installation_id: 42 } : { id: "r1" };
  Object.assign(q, { select: () => q, eq: () => q, maybeSingle: async () => ({ data: one, error: null }),
    then: (res: (v: unknown) => unknown) => res({ data: [{ full_name: "acme/app" }], error: null }) });
  return q;
} }) }));

import { openFindingFixPr } from "./findingFixPr";
import { previewRepair } from "./preview";

const EDITED = "alter policy read on public.orders using (auth.uid() = user_id);\n";
const writes: { method: string; url: string; body: Record<string, unknown> }[] = [];
let created = false;
beforeEach(() => {
  writes.length = 0; created = false;
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      writes.push({ method, url, body: JSON.parse(String(init?.body ?? "{}")) });
      if (url.endsWith("/git/refs")) created = true;
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/12" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return created ? new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => vi.unstubAllGlobals());

describe("fix-card preview parity (Q13-F)", () => {
  it("shows the edited migration the click commits, and writes nothing itself", async () => {
    const preview = await previewRepair("u1", { action: "finding-fix-pr", repositoryId: "r1", findingId: finding.id, editedContent: EDITED });
    expect(writes).toEqual([]);
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    await openFindingFixPr("u1", finding.id, EDITED, "r1");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    expect(preview.files).toEqual([{ path: decodeURIComponent(put.url.split("/contents/")[1]), change: "add", before: null, after: EDITED }]);
    expect(Buffer.from(String(put.body.content), "base64").toString("utf8")).toBe(EDITED);
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
  });
});
