import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";
import { scanPatches } from "@/lib/deep/historyScan";
import { scanSecrets } from "@/lib/deep/githubScan";

// Dogfood (2026-10-19): ShipLock's own history check reported a realistic AWS
// key fixture in lib/deep/githubScan.test.ts. By the product's own rule that
// is right: a real-looking value in a test file still reports, and every
// commit touching such a file adds another. Fixtures build realistic values at
// runtime ("sk_" + "live_..."), so no source line holds one.
const roots = ["app", "components", "lib", "scripts", "mcp", "proxy.ts"];
const files = (path: string): string[] => {
  try {
    return readdirSync(path, { withFileTypes: true }).flatMap((entry) =>
      entry.name === "node_modules" ? [] : files(join(path, entry.name)));
  } catch {
    return /\.(ts|tsx|mjs|js)$/.test(path) ? [path] : [];
  }
};

it("holds no source line that ShipLock's own history scan would report", () => {
  const reported = roots.flatMap(files).flatMap((file) =>
    readFileSync(file, "utf8").split("\n").flatMap((line, index) =>
      scanPatches([{ sha: "0".repeat(40), message: "", date: "", patch: `diff --git a/${file} b/${file}\n+${line}` }])
        .map((hit) => `${file}:${index + 1} ${hit.secretId}`)));
  expect(reported).toEqual([]);
});

// The working-tree check reads the same files and reports a realistic value
// in a test file as "possible" (2026-10-20: an OpenAI-format fixture in
// githubScan.test.ts stayed on ShipLock's own Issues). Same rule: build it at
// runtime.
it("holds no file that ShipLock's own committed secrets check would report", () => {
  const reported = roots.flatMap(files)
    .flatMap((path) => scanSecrets([{ path, content: readFileSync(path, "utf8") }]))
    .filter((finding) => finding.id.startsWith("github:secret:"))
    .map((finding) => finding.id);
  expect(reported).toEqual([]);
});
