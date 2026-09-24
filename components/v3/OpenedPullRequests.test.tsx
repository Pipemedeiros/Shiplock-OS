import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { OpenedPullRequests } from "./OpenedPullRequests";

const item = (over = {}) => ({ id: "a", lane: "Fix", repository: "acme/app", number: 9,
  url: "https://github.com/acme/app/pull/9", mergedAt: null as string | null, requestedAt: "2026-09-20T10:00:00.000Z", ...over });

describe("OpenedPullRequests (Q1 / 8-R2)", () => {
  it("shows open and merged pull requests, and that a merge queues a recheck", () => {
    const html = renderToStaticMarkup(<OpenedPullRequests opened={{ available: true,
      items: [item(), item({ id: "b", number: 10, url: "https://github.com/acme/app/pull/10", mergedAt: "2026-09-23T12:00:00.000Z" })] }} />);
    expect(html).toContain("Waiting for your review");
    expect(html).toContain("Merged 2026-09-23 12:00 UTC. ShipLock is rechecking the default branch.");
    expect(html).toContain("#9");
    expect(html).toContain("https://github.com/acme/app/pull/10");
    expect(html).not.toMatch(/[–—]| - /);
  });
  it("says when nothing was opened, and when the list could not load", () => {
    expect(renderToStaticMarkup(<OpenedPullRequests opened={{ available: true, items: [] }} />)).toMatch(/only after you click/);
    expect(renderToStaticMarkup(<OpenedPullRequests opened={{ available: false, items: [] }} />)).toMatch(/could not load/i);
  });

  it("shows the customer's CI for open pull requests, labeled as not run by ShipLock", () => {
    const html = renderToStaticMarkup(<OpenedPullRequests opened={{ available: true, items: [item(), item({ id: "b" }), item({ id: "c" }), item({ id: "d" }), item({ id: "e" })] }}
      ci={{ a: "passing", b: "failing", c: "pending", d: "none_visible", e: "unknown" }} />);
    expect(html).toContain("CI, not run by ShipLock: passing");
    expect(html).toContain("CI, not run by ShipLock: failing");
    expect(html).toContain("CI, not run by ShipLock: still running");
    expect(html).toContain("CI, not run by ShipLock: no checks visible");
    expect(html).toContain("CI, not run by ShipLock: unknown");
  });
});
