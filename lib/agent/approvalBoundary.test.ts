import { expect, it } from "vitest";
import { readFileSync } from "node:fs";

it("repository audits cannot open branches or pull requests without a separate click", () => {
  const audit = readFileSync(new URL("./audit.ts", import.meta.url),"utf8");
  expect(audit).not.toMatch(/openFixPullRequests|runFixPr|openPullRequest|createBranch/);
  expect(audit).toContain("Opening a branch/PR is a separate, explicit");
});
