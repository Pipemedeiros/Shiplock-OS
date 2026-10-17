import { describe, expect, it } from "vitest";
import { MAX_PATHS, calledPaths, liveCaller } from "./shippedCalls";

// P5: the paths the live site's own JavaScript names, read from the scripts
// the bundle audit already downloads. Paths only: a query string or anything
// that is not a plain path never leaves the customer's bundle.
describe("calledPaths", () => {
  it("keeps the API paths minified code builds, with and without a template hole", () => {
    const js = 'fetch("/api/orders/"+e);fetch(`/api/items/${id}/share`);r.get("/api/me");o.push("/dashboard")';
    expect(calledPaths(js)).toEqual(["/api/items/", "/api/me", "/api/orders/", "/dashboard"]);
  });

  it("drops query strings and fragments, keeping the path", () => {
    expect(calledPaths('fetch("/api/search?q=secret-term&token=abc");a="/docs#top"')).toEqual(["/api/search", "/docs"]);
  });

  it("ignores build assets, protocol-relative URLs, regex-like and odd strings", () => {
    const js = 'a="/_next/static/chunks/1.js";h="/_next";b="//cdn.example.com/x";c="/logo.svg";d="/";e="/a b";f="/x\\"y";g="/fonts/inter.woff2"';
    expect(calledPaths(js)).toEqual([]);
  });

  it("is bounded in count and length", () => {
    const many = Array.from({ length: MAX_PATHS + 50 }, (_, i) => `"/api/p${i}"`).join(";");
    expect(calledPaths(many)).toHaveLength(MAX_PATHS);
    expect(calledPaths(`"/${"a".repeat(300)}"`)).toEqual([]);
  });
});

describe("liveCaller", () => {
  const paths = ["/api/items/", "/api/me", "/settings"];

  it("matches a static route exactly and a dynamic route by its fixed prefix", () => {
    expect(liveCaller("/api/me", paths)).toBe("/api/me");
    expect(liveCaller("/api/items/[id]", paths)).toBe("/api/items/");
    expect(liveCaller("/api/items/[id]/share", paths)).toBe("/api/items/");
  });

  it("never matches what the bundle does not name", () => {
    expect(liveCaller("/api/admin", paths)).toBeNull();
    expect(liveCaller("/api/m", paths)).toBeNull();
    expect(liveCaller("/api/[...all]", paths)).toBeNull();
  });

  it("does not claim server actions or tRPC procedures, which ship without a path", () => {
    expect(liveCaller("action:app/actions.ts#save", paths)).toBeNull();
    expect(liveCaller("trpc:server/router.ts#me", paths)).toBeNull();
  });

  it("reads a duplicated route name the way the inventory writes it", () => {
    expect(liveCaller("apps/web:/api/me", paths)).toBe("/api/me");
  });
});
