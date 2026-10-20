import { describe, expect, it } from "vitest";
import { productionLine } from "./productionLine";

describe("ProductionLine (is it live?)", () => {
  const read = (over: Record<string, unknown> = {}) => ({ deploy: { state: "read" as const, environment: "Production", host: "vercel",
    headSha: "f".repeat(40), live: { sha: "b".repeat(40), at: "2026-10-20T11:03:00Z" },
    latest: { sha: "b".repeat(40), state: "success" as const, at: "2026-10-20T11:03:00Z" }, behindBy: 3, ...over },
    ref: "main", checkedAt: "2026-10-20T12:00:00Z" });
  const text = (deploy: Parameters<typeof productionLine>[0]) => productionLine(deploy);

  it("says how many commits on the branch are not live", () => {
    expect(text(read())).toBe("Production runs bbbbbbb (vercel, 2026-10-20 11:03 UTC). main is 3 commits ahead of it, so they are not live.");
    expect(text(read({ behindBy: 1 }))).toMatch(/1 commit ahead of it, so it is not live/);
    expect(text(read({ behindBy: 0 }))).toBe("Production runs bbbbbbb, the head of main (vercel, 2026-10-20 11:03 UTC).");
  });

  it("names a newer deploy that failed or is still running", () => {
    expect(text(read({ latest: { sha: "c".repeat(40), state: "failure", at: "2026-10-20T12:05:00Z" } })))
      .toMatch(/^The newest production deploy, of ccccccc, failed\. Production still runs bbbbbbb/);
    expect(text(read({ latest: { sha: "c".repeat(40), state: "in_progress", at: "2026-10-20T12:05:00Z" } })))
      .toMatch(/^A production deploy of ccccccc is running\. Production still runs bbbbbbb/);
  });

  it("says unknown, never current, when it could not be read", () => {
    expect(text(read({ behindBy: null }))).toMatch(/history has diverged.*unknown/);
    expect(text(read({ live: null }))).toMatch(/No production deploy has succeeded/);
    expect(text({ deploy: { state: "none" }, ref: "main", checkedAt: "x" })).toMatch(/reports no production deploys to GitHub.*unknown/);
    expect(text({ deploy: { state: "unreadable", why: "No permission." }, ref: "main", checkedAt: "x" })).toBe("What is live is unknown. No permission.");
    expect(text(null)).toMatch(/not been checked/);
    for (const t of [text(read()), text(read({ behindBy: null })), text(null)]) expect(t).not.toMatch(/ [-–—] /);
  });
});
