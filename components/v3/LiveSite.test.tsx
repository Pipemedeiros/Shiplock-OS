import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { LiveSite, liveSiteStatus } from "./LiveSite";
import type { LiveReach } from "@/lib/chain/liveReach";

const live: LiveReach = { repositoryId: "r1", host: "app.acme.com", observedAt: "2026-10-20T09:21:04.709Z", paths: [],
  requests: ["/api/me"], read: { pages: 4, scriptsSeen: 11, scriptsRead: 11 } };
const html = (props: Parameters<typeof LiveSite>[0]) => renderToStaticMarkup(<LiveSite {...props} />);

describe("LiveSite (outside view, shadow routes)", () => {
  it("lists addresses the live site requests that the repository lacks, as not checked", () => {
    const out = html({ live, repository: "acme/app", shadow: { state: "read", paths: ["/api/legacy/export"], partial: false, removed: [] } });
    expect(out).toContain("/api/legacy/export");
    expect(out).toContain("acme/app");
    expect(out).toMatch(/not checked/i);
    expect(out).toContain("4 pages, 11 of 11 scripts");
    expect(liveSiteStatus(live, { state: "read", paths: ["/api/a", "/api/b"], partial: false, removed: [] })).toBe("2 not in the repository");
  });

  it("never reads as clean: an empty list names what it covers, partial and unknown say so", () => {
    const empty = html({ live, repository: "acme/app", shadow: { state: "read", paths: [], partial: false, removed: [] } });
    expect(empty).toMatch(/built at runtime/i);
    expect(empty).not.toMatch(/secure|safe|clean/i);
    const partial = html({ live: { ...live, read: { pages: 1, scriptsSeen: 30, scriptsRead: 24 } }, repository: "acme/app",
      shadow: { state: "read", paths: [], partial: true, removed: [] } });
    expect(partial).toMatch(/24 of 30 scripts/);
    expect(partial).toMatch(/rest are unknown/i);
    const unknown = html({ live, repository: "acme/app", shadow: { state: "unknown", why: "No audit of this repository stored its routes." } });
    expect(unknown).toContain("No audit of this repository stored its routes.");
    expect(liveSiteStatus(live, { state: "unknown", why: "x" })).toBe("Unknown");
    expect(liveSiteStatus(live, { state: "read", paths: [], partial: true, removed: [] })).toBe("Partly read");
  });

  it("says when the live build still requests a route the code removed", () => {
    const shadow = { state: "read" as const, paths: ["/api/legacy/export"], partial: false, removed: ["/api/legacy/export"] };
    const out = html({ live, repository: "acme/app", shadow });
    expect(out).toContain("Removed from acme/app, still live.");
    expect(out).toMatch(/older than your code/);
    expect(liveSiteStatus(live, shadow)).toBe("1 removed from code, still live");
  });

  it("offers the binding when no address is bound", () => {
    const out = html({ live: null, repository: null, shadow: { state: "unknown", why: "No app address is bound to this repository." } });
    expect(out).toContain("/dashboard/settings");
    expect(liveSiteStatus(null, { state: "unknown", why: "x" })).toBe("Not bound");
  });

  it("uses no dashes in its copy", () => {
    const out = html({ live, repository: "acme/app", shadow: { state: "read", paths: [], partial: false, removed: [] } });
    expect(out.replace(/<[^>]+>/g, "")).not.toMatch(/ [-–—] /);
  });
});
