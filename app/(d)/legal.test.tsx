import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import Privacy from "./privacy/page";
import Terms from "./terms/page";

// Q28 (Felipe 2026-09-29): privacy and terms must match the product as it is:
// GitHub App, customer AI, traffic snippet, proofs on a disposable copy,
// cookie choice, welcome email. v3 frame, plain words, no dashes.
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

describe("privacy policy", () => {
  const html = renderToStaticMarkup(<Privacy />);
  const t = text(html);
  it("describes what the product actually reads and stores", () => {
    for (const fact of ["GitHub App", "your own AI", "traffic snippet", "user agent", "disposable copy", "Reject", "welcome email",
      "never read the rows", "support@shiplock.dev"]) expect(t, fact).toContain(fact);
    expect(t).not.toMatch(/anon \(public\) key you paste/);
  });
  it("lists sub-processors including the conditional ones", () => {
    for (const name of ["Supabase", "Vercel", "GitHub", "Resend", "PostHog", "Stripe"]) expect(t).toContain(name);
    expect(t).toMatch(/only after you accept/i);
  });
  // ShipLock makes no model call (Felipe, 2026-10-01): no model provider is a
  // sub-processor, and no customer key is stored for AI.
  it("names no model provider as a sub-processor and offers no saved key", () => {
    expect(t).not.toContain("Anthropic");
    expect(t).not.toMatch(/API key you\s+save|key is encrypted at rest and used/i);
    expect(t).toContain("ShipLock makes no AI calls of its own");
  });
  it("is in the v3 frame, dated, links terms, and has no dashes", () => {
    expect(html).toContain('class="v3');
    expect(t).toContain("Last updated 2026-10-05");
    expect(html).toContain('href="/terms"');
    expect(t).not.toMatch(/[–—]/);
  });
});

describe("terms of service", () => {
  const html = renderToStaticMarkup(<Terms />);
  const t = text(html);
  it("covers authorization, approvals, proofs, AI, and what a result does not mean", () => {
    for (const fact of ["authorize", "never merges or deploys", "disposable copy", "your own AI", "does not mean your application is secure",
      "Free", "traffic snippet"]) expect(t, fact).toContain(fact);
  });
  it("is in the v3 frame, dated, links privacy, and has no dashes", () => {
    expect(html).toContain('class="v3');
    expect(t).toContain("Last updated 2026-09-30");
    expect(html).toContain('href="/privacy"');
    expect(t).not.toMatch(/[–—]/);
  });
});
