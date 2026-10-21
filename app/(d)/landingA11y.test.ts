import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Q41 and Q33 (2026-09-30, from Lighthouse on shiplock.dev): the reasoning
// animation faded its pending steps to 28% opacity (contrast 1.8 to 2.4 on
// navy), and the header links wrapped onto two lines at phone width.
const css = readFileSync("app/(d)/v3.css", "utf8");
const block = (selector: string) => css.match(new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{([^}]*)\\}`))?.[1] ?? "";

describe("landing accessibility", () => {
  // 2026-10-21: the agent session replaced the reasoning animation; its muted
  // text keeps 4.5:1 on #0a1422 (#8a9bb0 is 6.5:1, #7f8fa3 is 5.6:1).
  it("keeps the agent session's muted text legible on its dark panel", () => {
    expect(block(".v3-sess")).toMatch(/background:\s*#0a1422/);
    expect(block(".v3-sess-line small")).toMatch(/color:\s*#8a9bb0/);
    expect(block(".v3-sess-tag")).toMatch(/color:\s*#7f8fa3/);
    expect(block(".v3-sess-line")).not.toMatch(/opacity:\s*\.?[0-2]/);
  });

  it("hides the secondary header links on phones so the header stays on one line", () => {
    expect(css).toMatch(/@media \(max-width: 560px\)\s*\{[^}]*\.v3-nav-links \.v3-nav-secondary\s*\{\s*display:\s*none/);
    const page = readFileSync("app/(d)/page.tsx", "utf8");
    expect(page).toMatch(/className="v3-nav-secondary"[^>]*>How it works/);
    expect(page).toMatch(/className="v3-nav-secondary"[^>]*>What it covers/);
  });

  it("keeps the 28px side gutter on every section and the footer (no edge-to-edge text on phones)", () => {
    expect(block(".v3-section")).not.toMatch(/padding:\s*\d+px 0\b/);
    expect(readFileSync("app/(d)/page.tsx", "utf8")).not.toMatch(/className="v3-shell"[^>]*padding: "\d+px 0"/);
  });

  it("section labels (eyebrows) pass 4.5:1 on the light backgrounds", () => {
    expect(block(".v3-eyebrow")).toMatch(/color:\s*#627085/);
  });
});
