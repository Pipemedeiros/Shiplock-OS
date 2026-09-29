import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/font/google", () => ({
  Geist: () => ({ variable: "font-geist" }),
  Geist_Mono: () => ({ variable: "font-geist-mono" }),
  Newsreader: () => ({ variable: "font-newsreader" }),
}));

import NotFound, { metadata } from "./not-found";

// The 404 a visitor sees for any unmatched URL (Felipe, 2026-09-29): the real
// ShipLock frame, what happened in plain words, and the ways back.
const html = renderToStaticMarkup(<NotFound />);

describe("the 404 page", () => {
  const text = html.replace(/<[^>]+>/g, " ");

  it("says the page does not exist and that nothing about the account changed", () => {
    expect(html).toContain("404");
    expect(text).toMatch(/This page does not exist/);
    expect(text).toMatch(/Nothing about your account, your repositories or your findings changed/);
  });

  it("offers the ways back, all to routes that exist", () => {
    for (const href of ['href="/"', 'href="/dashboard"', 'href="/onboarding"', 'href="/coverage"', 'href="/auth"']) {
      expect(html).toContain(href);
    }
  });

  it("carries the live brand frame and one main landmark with a single h1", () => {
    expect(html).toContain("v3-nav-top");
    expect(html).toContain("ShipLock");
    expect(html.match(/<main/g)).toHaveLength(1);
    expect(html.match(/<h1/g)).toHaveLength(1);
  });

  it("is not indexed and uses no dashes in copy", () => {
    expect(metadata.robots).toMatchObject({ index: false, follow: false });
    expect(text).not.toMatch(/[–—]/);
  });
});

// `.v3 a { color: inherit }` outranks `.v3-primary`, so a Link styled as the
// primary button rendered dark text on bronze (landing and 404, seen in a
// headless screenshot 2026-09-29). Link buttons keep their own colour.
describe("link buttons keep their colour", () => {
  const css = readFileSync("app/(d)/v3.css", "utf8");
  it("declares the primary and on-dark colours for anchors", () => {
    expect(css).toMatch(/\.v3 a\.v3-primary\s*\{[^}]*color:\s*#fff/);
    expect(css).toMatch(/\.v3 a\.v3-ondark\s*\{[^}]*color:\s*#eef2f7/);
  });
  it("gives the 404's second action a visible outline", () => {
    expect(html).toMatch(/class="v3-btn v3-ghost"[^>]*>Go to the home page/);
  });
});
