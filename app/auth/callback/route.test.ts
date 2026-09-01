import { describe, expect, it } from "vitest";
import { safeNext, jsonForScript } from "./route";

/**
 * The sign-in window renders a page carrying `next`, and `next` comes from the
 * query string. Both helpers below exist because the first version of that page
 * interpolated it straight into a <script> and handed it to location.replace —
 * an open redirect and a script injection, in the callback of the auth flow, in
 * a product that scans other people's code for exactly this.
 */

describe("safeNext", () => {
  it("keeps an ordinary path", () => {
    expect(safeNext("/dashboard")).toBe("/dashboard");
    expect(safeNext("/dashboard/risks?tab=open")).toBe("/dashboard/risks?tab=open");
  });

  it("falls back when nothing was asked for", () => {
    expect(safeNext(null)).toBe("/onboarding");
    expect(safeNext("")).toBe("/onboarding");
  });

  it("refuses an absolute URL", () => {
    expect(safeNext("https://evil.example/steal")).toBe("/onboarding");
    expect(safeNext("http://evil.example")).toBe("/onboarding");
  });

  it("refuses a protocol-relative URL", () => {
    // The classic open redirect: the browser reads //host as a real host.
    expect(safeNext("//evil.example")).toBe("/onboarding");
  });

  it("refuses the backslash form browsers normalise to it", () => {
    expect(safeNext("/\\evil.example")).toBe("/onboarding");
  });

  it("refuses a javascript: URL", () => {
    // This one RUNS, because the completion page navigates itself to `next`.
    expect(safeNext("javascript:alert(document.cookie)")).toBe("/onboarding");
    expect(safeNext("  javascript:alert(1)")).toBe("/onboarding");
  });

  it("refuses a data: URL", () => {
    expect(safeNext("data:text/html,<script>alert(1)</script>")).toBe("/onboarding");
  });
});

describe("jsonForScript", () => {
  it("escapes a closing script tag", () => {
    const out = jsonForScript({ next: "</script><script>alert(1)</script>" });
    expect(out).not.toContain("</script>");
    expect(out).not.toContain("<");
    expect(JSON.parse(out.replace(/\\u003c/g, "<").replace(/\\u003e/g, ">"))).toEqual({
      next: "</script><script>alert(1)</script>",
    });
  });

  it("escapes the line separators a JavaScript parser treats as newlines", () => {
    const out = jsonForScript({ v: "a b c" });
    expect(out).not.toContain(" ");
    expect(out).not.toContain(" ");
  });

  it("still produces valid JSON for ordinary values", () => {
    expect(JSON.parse(jsonForScript({ source: "shiplock-auth", ok: true, next: "/onboarding" }))).toEqual({
      source: "shiplock-auth",
      ok: true,
      next: "/onboarding",
    });
  });
});
