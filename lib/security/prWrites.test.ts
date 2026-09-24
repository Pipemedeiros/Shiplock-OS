import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// AGENTS.md: every branch/PR write needs its own customer click and an audit
// receipt; ShipLock never opens a PR on its own. Only these modules may call
// GitHub's openPullRequest, and each is reachable only from the receipted
// repair worker (lib/jobs/repairWorker.ts). A new PR path, or a new caller of
// one, must be reviewed here first.
const PR_OPENERS = [
  "lib/deep/githubFixRun.ts",
  "lib/fixes/aiFixPr.ts",
  "lib/fixes/prRun.ts",
  "lib/fixes/pullRequestFixPr.ts",
  "lib/fixes/rateLimitPr.ts",
  "lib/fixes/riskFixPr.ts",
];
const RECEIPTED_CALLERS = new Set(["lib/jobs/repairWorker.ts", "lib/fixes/findingFixPr.ts",
  // Q13: runs lanes only inside capturePreview, where no GitHub write is sent
  // (pinned by the capture-only test below and lib/deep/github.preview.test.ts).
  "lib/fixes/preview.ts"]);

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx|mjs)$/.test(name) && !/\.test\./.test(name) ? [path] : [];
  });
}
const all = ["lib", "app", "components", "mcp"].flatMap(sources);

describe("pull requests are opened only behind a customer click", () => {
  it("only the reviewed modules call openPullRequest", () => {
    const openers = all.filter((file) => file !== "lib/deep/github.ts" && /\bopenPullRequest\(/.test(readFileSync(file, "utf8")));
    expect(openers.sort()).toEqual(PR_OPENERS);
  });

  it("each PR module is imported only by the receipted repair path", () => {
    for (const opener of [...PR_OPENERS, "lib/fixes/findingFixPr.ts"]) {
      const stem = opener.replace(/^lib\//, "").replace(/\.ts$/, "");
      const base = stem.split("/").pop();
      const importers = all.filter((file) => file !== opener
        && new RegExp(`from "(@/lib/${stem}|\\./${base})"`).test(readFileSync(file, "utf8")));
      for (const importer of importers) expect({ opener, importer, allowed: RECEIPTED_CALLERS.has(importer) }).toEqual({ opener, importer, allowed: true });
    }
  });

  it("the preview module runs lanes only inside capturePreview (Q13)", () => {
    const code = readFileSync("lib/fixes/preview.ts", "utf8");
    expect(code).toMatch(/capturePreview\(\(\) => runLane\(userId, request\)\)/);
    expect(code.match(/\brunLane\(/g)?.length).toBe(2);
    expect(code).not.toMatch(/export (async )?function runLane/);
    expect(code).not.toMatch(/\bopenPullRequest\(|\bputFile\(|\bcreateBranch\(/);
  });
});
