import { describe, expect, it } from "vitest";
import { buildRateLimitSuggestion } from "./rateLimitSuggestion";

// A reviewable, customer-side rate-limit change from observed
// traffic. One new helper file, off by default, fails open, never edits the
// customer's handlers or middleware; the PR body says what to do and how to undo.
const hot = { file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 480, paths: ["/api/orders/1", "/api/orders/2"] };
const files = ["app/api/orders/[id]/route.ts", "package.json"];

describe("buildRateLimitSuggestion", () => {
  it("adds one helper file that is off by default and fails open", () => {
    const s = buildRateLimitSuggestion(hot, files, { windowHours: 6 });
    expect(s.kind).toBe("pr");
    if (s.kind !== "pr") return;
    expect(s.files.map((f) => f.path)).toEqual(["lib/shiplock-rate-limit.ts"]);
    const helper = s.files[0].content;
    expect(helper).toContain('if (process.env.SHIPLOCK_RATE_LIMIT !== "on") return null;');
    expect(helper).toMatch(/catch[\s\S]*return null/);
    expect(helper).not.toMatch(/fetch\(|shiplock\.dev/);
    expect(s.title).toBe("Rate limit /api/orders/:id (suggested by ShipLock)");
  });
  it("puts the evidence, the change, how to turn it on and off, and the unverified label in the body", () => {
    const s = buildRateLimitSuggestion(hot, files, { windowHours: 6 });
    if (s.kind !== "pr") throw new Error("expected a PR");
    expect(s.body).toContain("480 suspicious requests");
    expect(s.body).toContain("/api/orders/1");
    expect(s.body).toContain("app/api/orders/[id]/route.ts");
    expect(s.body).toContain("SHIPLOCK_RATE_LIMIT=on");
    expect(s.body).toMatch(/Unverified/);
    expect(s.body).toMatch(/does not change any existing file/i);
    expect(s.body).not.toMatch(/[–—]/);
  });
  it("refuses when a helper with that name already exists", () => {
    expect(buildRateLimitSuggestion(hot, [...files, "lib/shiplock-rate-limit.ts"], { windowHours: 6 }))
      .toEqual({ kind: "refused", reason: "helper_exists" });
  });
  it("uses src/lib when the repository keeps code under src", () => {
    const s = buildRateLimitSuggestion({ ...hot, file: "src/app/api/orders/[id]/route.ts" }, ["src/app/api/orders/[id]/route.ts"], { windowHours: 6 });
    if (s.kind !== "pr") throw new Error("expected a PR");
    expect(s.files[0].path).toBe("src/lib/shiplock-rate-limit.ts");
  });
});
