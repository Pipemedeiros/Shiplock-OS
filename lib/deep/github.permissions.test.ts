import { describe, expect, it } from "vitest";
import { missingInstallationPermissions } from "./github";

describe("GitHub App permission contract", () => {
  it("requires the reads and reviewable-write surfaces the product actually uses", () => {
    expect(missingInstallationPermissions({
      metadata: "read",
      contents: "write",
      pull_requests: "write",
      checks: "write",
    })).toEqual([]);
  });

  it("does not call contents read-only while fix branches require writes", () => {
    expect(missingInstallationPermissions({
      metadata: "read",
      contents: "read",
      pull_requests: "write",
      checks: "write",
    })).toEqual(["contents"]);
  });

  it("reports every missing capability without exposing credentials", () => {
    expect(missingInstallationPermissions({ metadata: "read" })).toEqual([
      "contents",
      "pull_requests",
      "checks",
    ]);
  });
});
