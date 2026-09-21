import { describe, expect, it } from "vitest";
import { decodeAuthNext, encodeAuthNext, safeNext } from "./authRedirect";

describe("Section 4 / Step 4A: post-auth return paths", () => {
  it("keeps ordinary local paths, queries and fragments", () => {
    expect(safeNext("/dashboard")).toBe("/dashboard");
    expect(safeNext("/dashboard/risks?tab=open#finding")).toBe("/dashboard/risks?tab=open#finding");
  });

  it.each([
    null,
    "",
    "https://evil.example/steal",
    "//evil.example",
    "/\\evil.example",
    "/safe\\evil.example",
    "javascript:alert(1)",
    "data:text/html,hi",
    "/safe\nSet-Cookie: bad=1",
  ])("refuses an unsafe return path: %s", (value) => {
    expect(safeNext(value)).toBe("/onboarding");
  });

  it("supports an explicit safe fallback for direct sign-in", () => {
    expect(safeNext(undefined, "/dashboard")).toBe("/dashboard");
  });

  it("round-trips the short-lived OAuth cookie and refuses malformed encoding", () => {
    expect(decodeAuthNext(encodeAuthNext("/onboarding?from=home"))).toBe("/onboarding?from=home");
    expect(decodeAuthNext("%E0%A4%A")).toBeNull();
  });
});
