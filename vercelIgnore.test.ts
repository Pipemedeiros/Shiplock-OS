import { execSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";

// 2026-10-20: 224 production builds in 30 days, many for ledger or skill
// commits that change nothing deployed. Vercel skips a build when its
// ignoreCommand exits 0; any other exit, including a missing parent, builds.
const command = JSON.parse(readFileSync("vercel.json", "utf8")).ignoreCommand as string;

function skips(change: (dir: string) => void, since?: "base"): boolean {
  const dir = mkdtempSync(join(tmpdir(), "vercel-ignore-"));
  const git = (args: string) => execSync(`git ${args}`, { cwd: dir, stdio: "pipe" });
  git("init -q"); git("config user.email t@t"); git("config user.name t");
  mkdirSync(join(dir, "docs")); mkdirSync(join(dir, "lib"));
  writeFileSync(join(dir, "docs/ledger.md"), "a"); writeFileSync(join(dir, "lib/x.ts"), "a");
  git("add -A"); git("commit -qm base");
  const base = git("rev-parse HEAD").toString().trim();
  change(dir);
  git("add -A"); git("commit -qm next --allow-empty");
  // A push of several commits: Vercel builds only the newest, so the check is
  // against the last commit it deployed, not the parent.
  if (since) { writeFileSync(join(dir, "docs/ledger.md"), "c"); git("add -A"); git("commit -qm ledger"); }
  const env = { ...process.env, VERCEL_GIT_PREVIOUS_SHA: since ? base : "" };
  try { execSync(command, { cwd: dir, stdio: "pipe", env, shell: "/bin/sh" }); return true; } catch { return false; }
}

it("skips a build when a commit changes only docs, skills or Markdown", () => {
  expect(skips((dir) => writeFileSync(join(dir, "docs/ledger.md"), "b"))).toBe(true);
  expect(skips(() => {})).toBe(true);
});

it("builds when anything deployed changes", () => {
  expect(skips((dir) => writeFileSync(join(dir, "lib/x.ts"), "b"))).toBe(false);
});

it("builds a push whose newest commit is docs but an earlier one is code", () => {
  expect(skips((dir) => writeFileSync(join(dir, "lib/x.ts"), "b"), "base")).toBe(false);
});
