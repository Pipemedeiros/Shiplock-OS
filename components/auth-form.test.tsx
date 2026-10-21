import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/lib/supabaseBrowser", () => ({ getSupabaseBrowser: () => ({}) }));
const { AuthForm } = await import("./auth-form");

// The sign-in card is the first screen after the landing page; it wears v3
// (hairline card, no shadow, bronze only on the one primary action).
describe("AuthForm", () => {
  const html = renderToStaticMarkup(<AuthForm oauthError={false} nextPath="/dashboard" />);

  it("uses v3 primitives, not Design D", () => {
    expect(html).not.toContain("dxd");
    expect(html).toMatch(/^<div class="v3-card v3-auth"/);
    expect(html).toMatch(/<h1 class="v3-serif">Sign in<\/h1>/);
  });

  it("keeps labelled fields and a single bronze action", () => {
    expect(html).toMatch(/<label for="auth-email">Email<\/label><input id="auth-email" type="email"[^>]*class="v3-input"/);
    expect(html).toMatch(/<label for="auth-pass">Password<\/label><input id="auth-pass" type="password"[^>]*class="v3-input"/);
    expect(html.match(/v3-primary/g)).toHaveLength(1);
    expect(html).toMatch(/type="submit"[^>]*class="v3-btn v3-primary v3-auth-wide"/);
    expect(html.match(/class="v3-btn v3-ghost v3-auth-wide"/g)).toHaveLength(2);
  });

  it("states the OAuth failure in the crit tone", () => {
    const failed = renderToStaticMarkup(<AuthForm oauthError nextPath="/dashboard" />);
    expect(failed).toMatch(/<p class="v3-auth-error" role="alert">/);
  });
});
