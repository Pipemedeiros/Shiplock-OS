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
let failPulls = 0;
// Files written to the fix branch, so a retry can see what an earlier attempt left.
const branchFiles = new Map<string, string>();
const STAMP = /\d{14}/;
beforeEach(() => {
  writes.length = 0; created = false; failPulls = 0; branchFiles.clear();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method !== "GET") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      writes.push({ method, url, body });
      if (url.endsWith("/git/refs")) created = true;
      if (method === "PUT") branchFiles.set(decodeURIComponent(url.split("/contents/")[1]), String(body.content));
      if (url.endsWith("/pulls") && failPulls-- > 0) return new Response("{}", { status: 502 });
      return new Response(JSON.stringify(url.endsWith("/pulls") ? { html_url: "https://github.com/acme/app/pull/12" } : {}), { status: 201 });
    }
    if (url.includes("/git/ref/heads/main")) return new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 });
    if (url.includes("/git/ref/heads/shiplock")) return created ? new Response(JSON.stringify({ object: { sha: "a".repeat(40) } }), { status: 200 }) : new Response("{}", { status: 404 });
    if (url.includes("/pulls?")) return new Response("[]", { status: 200 });
    const onFixBranch = /[?&]ref=shiplock/.test(url);
    if (onFixBranch && /\/contents\/supabase\/migrations\?/.test(url)) {
      return new Response(JSON.stringify([...branchFiles.keys()].map((p) => ({ type: "file", name: p.split("/").pop() }))), { status: 200 });
    }
    const file = /\/contents\/([^?]+)\?/.exec(url)?.[1];
    if (onFixBranch && file && branchFiles.has(decodeURIComponent(file))) {
      return new Response(JSON.stringify({ sha: "blob", encoding: "base64", content: branchFiles.get(decodeURIComponent(file)) }), { status: 200 });
    }
    return new Response("{}", { status: 404 });
  }));
});
afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("fix-card preview parity (Q13-F, Q8)", () => {
  it("shows the edited migration the click commits, and writes nothing itself, even across a second boundary", async () => {
    vi.setSystemTime(new Date("2026-09-28T12:00:00.999Z"));
    const preview = await previewRepair("u1", { action: "finding-fix-pr", repositoryId: "r1", findingId: finding.id, editedContent: EDITED });
    expect(writes).toEqual([]);
    if (preview.status !== "planned") throw new Error(`expected a plan, got ${JSON.stringify(preview)}`);
    vi.setSystemTime(new Date("2026-09-28T12:00:01.001Z"));
    await openFindingFixPr("u1", finding.id, EDITED, "r1");
    const put = writes.find((w) => w.method === "PUT")!;
    const pr = writes.find((w) => w.url.endsWith("/pulls"))!;
    const committed = decodeURIComponent(put.url.split("/contents/")[1]);
    // The name's timestamp is set at click, and the preview says so; everything else matches.
    expect(preview.files).toEqual([{ path: expect.stringMatching(STAMP), change: "add", before: null, after: EDITED, nameSetAtClick: true }]);
    expect(preview.files[0].path.replace(STAMP, "")).toBe(committed.replace(STAMP, ""));
    expect(Buffer.from(String(put.body.content), "base64").toString("utf8")).toBe(EDITED);
    expect({ title: preview.title, body: preview.body, branch: preview.branch, base: preview.base })
      .toEqual({ title: pr.body.title, body: pr.body.body, branch: pr.body.head, base: pr.body.base });
  });

  it("a retried click after GitHub fails to open the PR commits the migration once", async () => {
    failPulls = 1;
    vi.setSystemTime(new Date("2026-09-28T12:00:00.500Z"));
    await expect(openFindingFixPr("u1", finding.id, EDITED, "r1")).rejects.toThrow("502");
    vi.setSystemTime(new Date("2026-09-28T12:00:05.000Z"));
    await openFindingFixPr("u1", finding.id, EDITED, "r1");
    const puts = writes.filter((w) => w.method === "PUT").map((w) => decodeURIComponent(w.url.split("/contents/")[1]));
    expect(puts).toEqual(["supabase/migrations/20260928120000_shiplock_orders-readable-by-anyone.sql"]);
    expect(writes.filter((w) => w.url.endsWith("/pulls"))).toHaveLength(2);
  });
});
