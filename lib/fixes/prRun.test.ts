import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/deep/github", () => ({
  getInstallationToken: vi.fn(),
  listRepos: vi.fn(),
  getBranchSha: vi.fn(async () => "basesha"),
  createBranch: vi.fn(async () => {}),
  putFile: vi.fn(async () => {}),
  openPullRequest: vi.fn(async () => "https://github.com/o/r/pull/1"),
}));

import { openFixPr } from "./prRun";
import * as gh from "@/lib/deep/github";

/* eslint-disable @typescript-eslint/no-explicit-any */
describe("openFixPr — safety invariants", () => {
  it("commits a new file to a fresh branch off default and opens a PR against default", async () => {
    const url = await openFixPr(
      "tok", "o/r", "main",
      { path: "supabase/migrations/x.sql", content: "ALTER TABLE t ENABLE ROW LEVEL SECURITY;" },
      "title", "body"
    );
    expect(url).toBe("https://github.com/o/r/pull/1");

    const branch = (gh.createBranch as any).mock.calls[0][2];
    expect(branch).toMatch(/^shiplock\/fix-/);
    expect(branch).not.toBe("main"); // never touches the default branch

    const putArgs = (gh.putFile as any).mock.calls[0];
    expect(putArgs[3]).toBe(branch); // committed to the fix branch
    expect(putArgs[5]).toBeUndefined(); // no sha → creating a new file

    const prArgs = (gh.openPullRequest as any).mock.calls[0];
    expect(prArgs[2]).toBe(branch); // head = fix branch
    expect(prArgs[3]).toBe("main"); // base = default (reviewable, never merged here)
  });
});
