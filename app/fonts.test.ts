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

  it("does not preload the older root fonts that only the error page uses", () => {
    const root = src("app/layout.tsx");
    const declarations = [...root.matchAll(/= \w+\(\{[\s\S]*?\}\);/g)].map((match) => match[0]);
    expect(declarations).toHaveLength(3);
    for (const declaration of declarations) expect(declaration).toMatch(/preload: false/);
  });

  it("keeps no styles that point at a font the layouts no longer load", () => {
    for (const css of ["app/(d)/design-base.css", "app/(d)/design-d.css", "app/(d)/v3.css"]) {
      expect(src(css), css).not.toMatch(/--dx-font-(hanken|fragment|chakra|jetbrains|bricolage|figtree)/);
    }
  });
});
