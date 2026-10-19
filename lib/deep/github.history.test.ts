import { afterEach, expect, it, vi } from "vitest";
import { listRecentCommitPatches } from "./github";
import { scanPatches } from "./historyScan";

afterEach(() => vi.unstubAllGlobals());

// Built at runtime so this file holds no key-shaped literal of its own. The
// test_ name is scaffolding a test file may hold; shipped code may not.
const realistic = "AKIA" + "2OGYQ7TL3MZ4PNWB";

function commitWith(filename: string) {
  return vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify([{ sha: "a".repeat(40), commit: { message: "m", author: { date: "2026-10-14T00:00:00Z" } } }]), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ files: [{ filename, patch: `@@ -1 +1 @@\n+const test_key = "${realistic}";` }] }), { status: 200 }));
}

// Production 2026-10-19: GitHub returns each file's patch without a diff
// header, so the history scan saw every added line with no path. A realistic
// fixture in a test file was then reported as a leaked key, with copy saying
// it was no longer in the files.
it("keeps each file's path, so the history scan can tell test scaffolding from shipped code", async () => {
  vi.stubGlobal("fetch", commitWith("lib/deep/githubScan.test.ts"));
  const [commit] = await listRecentCommitPatches("token", "acme/app", "main", 1);
  expect(commit.patch).toContain("diff --git a/lib/deep/githubScan.test.ts b/lib/deep/githubScan.test.ts");
  expect(scanPatches([commit])).toEqual([]);
});

it("still reports the same key added to shipped code", async () => {
  vi.stubGlobal("fetch", commitWith("lib/config.ts"));
  const commits = await listRecentCommitPatches("token", "acme/app", "main", 1);
  expect(scanPatches(commits).map((hit) => hit.secretId)).toEqual(["aws_key"]);
});
