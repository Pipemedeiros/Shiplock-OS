import { describe, expect, it } from "vitest";

/**
 * The cookie test that decides whether a request pays for a network call.
 *
 * Production served 41 gateway timeouts in 48 hours because the middleware
 * refreshed a Supabase session on every request, including anonymous hits on
 * the landing page where there was no session to refresh. Middleware runs in
 * front of every route, so a hang there took down static pages too.
 *
 * The regex is duplicated here rather than exported because middleware.ts runs
 * on the edge runtime and importing it into a node test drags that in. What
 * matters is that the SHAPES are pinned, so a change to Supabase's cookie
 * naming fails loudly here rather than quietly reintroducing the timeout.
 */
const SESSION_COOKIE = /^sb-.+-auth-token(\.\d+)?$/;

describe("session cookie detection", () => {
  it("recognises a Supabase session cookie", () => {
    expect(SESSION_COOKIE.test("sb-project-ref-auth-token")).toBe(true);
  });

  it("recognises the chunked form, which is what a real session uses", () => {
    // A session longer than 3180 characters is split, and the unchunked name
    // never appears. Missing this would skip the refresh for exactly the users
    // who are signed in.
    expect(SESSION_COOKIE.test("sb-project-ref-auth-token.0")).toBe(true);
    expect(SESSION_COOKIE.test("sb-project-ref-auth-token.1")).toBe(true);
  });

  it("ignores cookies that are not a session", () => {
    for (const name of [
      "sl_sb_state",
      "posthog",
      "sb-project-ref-auth-token-code-verifier",
      "auth-token",
      "sb-auth",
    ]) {
      expect(SESSION_COOKIE.test(name), name).toBe(false);
    }
  });
});
