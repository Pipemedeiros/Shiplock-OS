import { existsSync, readFileSync } from "node:fs";
import { expect, it } from "vitest";
import robots from "./robots";
import sitemap from "./sitemap";

// Felipe (2026-09-30): llms.txt, robots.txt and the sitemap must agree. Every
// sitemap URL is a real public page that robots allows; every page llms.txt
// names is in the sitemap; private pages are disallowed.
const paths = sitemap().map((entry) => new URL(entry.url).pathname);
const rules = robots().rules as { disallow: string[] };
const blocked = (path: string) => rules.disallow.some((rule) => path === rule || path.startsWith(rule.endsWith("/") ? rule : `${rule}/`) || path === rule.replace(/\/$/, ""));

it("lists only real pages that robots allows", () => {
  for (const path of paths) {
    expect(existsSync(path === "/" ? "app/(d)/page.tsx" : `app/(d)${path}/page.tsx`), path).toBe(true);
    expect(blocked(path), path).toBe(false);
  }
});

it("contains every page llms.txt names", () => {
  const named = [...readFileSync("public/llms.txt", "utf8").matchAll(/https:\/\/shiplock\.dev(\/[\w/-]*)/g)].map((m) => m[1]);
  for (const path of named) expect(paths, path).toContain(path);
});

it("keeps signed-in, one-off and private pages out of search", () => {
  for (const path of ["/dashboard", "/onboarding", "/auth", "/welcome", "/cancelled", "/api/", "/verified/"]) expect(rules.disallow).toContain(path);
});
