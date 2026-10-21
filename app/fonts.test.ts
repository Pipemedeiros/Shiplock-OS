import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Q34 (2026-09-29): Lighthouse on the live landing page measured 522 KiB of
// fonts in 19 files, 65% of the page, because every family ever tried was
// still loaded and preloaded. The v3 design uses Geist, Geist Mono and
// Newsreader; nothing else may be preloaded on every page.
const src = (path: string) => readFileSync(path, "utf8");
const loaders = (source: string) =>
  [...source.matchAll(/^const \w+ = (\w+)\(\{/gm)].map((match) => match[1]).sort();

describe("fonts", () => {
  it("loads only the v3 families in the product layout", () => {
    expect(loaders(src("app/(d)/layout.tsx"))).toEqual(["Geist", "Geist_Mono", "Newsreader"]);
  });

  // 2026-10-20: the root layout fetched Fraunces, Inter and IBM Plex Mono at
  // every build for the error page alone, and a failed Google Fonts fetch
  // broke a deploy and a CI run. The error page uses system fonts now.
  it("loads no Google font in the root layout, so a build fetches only the v3 families", () => {
    expect(loaders(src("app/layout.tsx"))).toEqual([]);
    expect(src("app/layout.tsx")).not.toMatch(/next\/font/);
    expect(src("app/error.tsx")).not.toMatch(/var\(--font-/);
  });

  it("keeps no styles that point at a font the layouts no longer load", () => {
    for (const css of ["app/(d)/design-base.css", "app/(d)/v3.css"]) {
      expect(src(css), css).not.toMatch(/--dx-font-(hanken|fragment|chakra|jetbrains|bricolage|figtree)/);
    }
  });
});
