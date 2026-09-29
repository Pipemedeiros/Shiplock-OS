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
describe("the 404 page", () => {
  const html = renderToStaticMarkup(<NotFound />);
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
