import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Felipe (2026-09-29): an llms.txt that tells AI assistants what ShipLock is,
// in the same plain voice as the site, pointing at pages that exist.
describe("llms.txt", () => {
  const text = readFileSync("public/llms.txt", "utf8");

  it("starts with the product name and a one-line summary", () => {
    expect(text).toMatch(/^# ShipLock\n\n> .+/);
  });

  it("links only to public pages that exist", () => {
    const paths = [...text.matchAll(/https:\/\/shiplock\.dev(\/[\w/-]*)/g)].map((m) => m[1]);
    expect(paths.length).toBeGreaterThan(2);
    for (const path of paths) {
      const page = path === "/" ? "app/(d)/page.tsx" : `app/(d)${path}/page.tsx`;
      expect(existsSync(page), path).toBe(true);
    }
  });

  it("uses no dashes and makes no security guarantee", () => {
    expect(text).not.toMatch(/[–—]/);
    expect(text).not.toMatch(/\b(guarantee|fully secure|100% secure)\b/i);
  });
});
