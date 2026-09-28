import { beforeEach, describe, expect, it, vi } from "vitest";

// Q8: a retried fix click must not stamp a second copy of the same fix file.
const state = vi.hoisted(() => ({
  branchExists: false,
  onBranch: new Map<string, string>(), // path -> content on the fix branch
  onBase: new Set<string>(), // paths on the default branch
  listError: false,
}));
vi.mock("@/lib/deep/github", () => ({
  getBranchSha: vi.fn(async (_t: string, _r: string, branch: string) => {
    if (branch === "main" || state.branchExists) return "sha";
    throw new Error("missing");
  }),
  createBranch: vi.fn(async () => {}),
  findOpenPullRequestForBranch: vi.fn(async () => null),
  listDirectory: vi.fn(async (_t: string, _r: string, dir: string) => {
    if (state.listError) throw new Error("GitHub contents HTTP 502");
    return [...state.onBranch.keys()].filter((p) => p.startsWith(`${dir}/`)).map((p) => p.slice(dir.length + 1));
  }),
  getFileSha: vi.fn(async (_t: string, _r: string, path: string, branch: string) =>
    (branch === "main" ? state.onBase.has(path) : state.onBranch.has(path)) ? "blob" : null),
  getFile: vi.fn(async (_t: string, _r: string, path: string) => state.onBranch.get(path) ?? null),
  putFile: vi.fn(async () => {}),
  openPullRequest: vi.fn(async () => "https://github.com/o/r/pull/1"),
}));

import { openFixPr } from "./prRun";
import * as gh from "@/lib/deep/github";

const SQL = "alter policy read on public.orders using (auth.uid() = user_id);\n";
const EARLIER = "supabase/migrations/20260928120000_shiplock_orders-readable-by-anyone.sql";
const NOW = "supabase/migrations/20260928120005_shiplock_orders-readable-by-anyone.sql";
const open = (path: string, content = SQL) => openFixPr("tok", "o/r", "main", { path, content }, "t", "b", `u\0f\0${content}`);

beforeEach(() => {
  vi.clearAllMocks();
  state.branchExists = false; state.onBranch.clear(); state.onBase.clear(); state.listError = false;
});

describe("openFixPr retry (Q8)", () => {
  it("reuses the fix file an earlier attempt wrote on the fix branch instead of stamping a second one", async () => {
    state.branchExists = true;
    state.onBranch.set(EARLIER, SQL);
    await open(NOW);
    expect(vi.mocked(gh.putFile)).not.toHaveBeenCalled();
    expect(vi.mocked(gh.openPullRequest)).toHaveBeenCalledOnce();
  });

  it("does not reuse a same-named fix already on the default branch (an earlier merged fix)", async () => {
    state.branchExists = true;
    state.onBranch.set(EARLIER, SQL);
    state.onBase.add(EARLIER);
    await open(NOW);
    expect(vi.mocked(gh.putFile).mock.calls.map((c) => c[2])).toEqual([NOW]);
  });

  it("reuses the same way for a code fix request file", async () => {
    state.branchExists = true;
    state.onBranch.set("shiplock-fixes/20260928120000-orders-readable-by-anyone.md", "# fix\n");
    await open("shiplock-fixes/20260928120005-orders-readable-by-anyone.md", "# fix\n");
    expect(vi.mocked(gh.putFile)).not.toHaveBeenCalled();
  });

  it("never renames a customer's own file or a file that is not stamped", async () => {
    state.branchExists = true;
    state.onBranch.set("supabase/migrations/20250101000000_init.sql", SQL);
    await open("supabase/migrations/20260928120005_init.sql");
    expect(vi.mocked(gh.listDirectory)).not.toHaveBeenCalled();
    expect(vi.mocked(gh.putFile).mock.calls.map((c) => c[2])).toEqual(["supabase/migrations/20260928120005_init.sql"]);
  });

  it("a fresh branch is not searched", async () => {
    await open(NOW);
    expect(vi.mocked(gh.listDirectory)).not.toHaveBeenCalled();
    expect(vi.mocked(gh.putFile).mock.calls.map((c) => c[2])).toEqual([NOW]);
  });

  it("fails for a retry, rather than writing a duplicate, when the branch cannot be listed", async () => {
    state.branchExists = true;
    state.onBranch.set(EARLIER, SQL);
    state.listError = true;
    await expect(open(NOW)).rejects.toThrow("502");
    expect(vi.mocked(gh.putFile)).not.toHaveBeenCalled();
  });
});
