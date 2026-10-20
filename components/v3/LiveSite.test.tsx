import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { LiveSite, liveSiteStatus } from "./LiveSite";
import type { LiveReach } from "@/lib/chain/liveReach";

const live: LiveReach = { repositoryId: "r1", host: "app.acme.com", observedAt: "2026-10-20T09:21:04.709Z", paths: [],
  requests: ["/api/me"], read: { pages: 4, scriptsSeen: 11, scriptsRead: 11 }, change: null };
const html = (props: Parameters<typeof LiveSite>[0]) => renderToStaticMarkup(<LiveSite {...props} />);

describe("LiveSite (outside view, shadow routes)", () => {
  it("lists addresses the live site requests that the repository lacks, as not checked", () => {
    const out = html({ live, repository: "acme/app", shadow: { state: "read", paths: ["/api/legacy/export"], partial: false, removed: [], codeUnread: false } });
    expect(out).toContain("/api/legacy/export");
    expect(out).toContain("acme/app");
    expect(out).toMatch(/not checked/i);
    expect(out).toContain("4 pages, 11 of 11 scripts");
    expect(liveSiteStatus(live, { state: "read", paths: ["/api/a", "/api/b"], partial: false, removed: [], codeUnread: false })).toBe("2 not in the repository");
  });

  it("never reads as clean: an empty list names what it covers, partial and unknown say so", () => {
    const empty = html({ live, repository: "acme/app", shadow: { state: "read", paths: [], partial: false, removed: [], codeUnread: false } });
    expect(empty).toMatch(/built at runtime/i);
    expect(empty).not.toMatch(/secure|safe|clean/i);
    const partial = html({ live: { ...live, read: { pages: 1, scriptsSeen: 30, scriptsRead: 24 } }, repository: "acme/app",
      shadow: { state: "read", paths: [], partial: true, removed: [], codeUnread: false } });
    expect(partial).toMatch(/24 of 30 scripts/);
    expect(partial).toMatch(/rest are unknown/i);
    const unknown = html({ live, repository: "acme/app", shadow: { state: "unknown", why: "No audit of this repository stored its routes." } });
    expect(unknown).toContain("No audit of this repository stored its routes.");
    expect(liveSiteStatus(live, { state: "unknown", why: "x" })).toBe("Unknown");
    expect(liveSiteStatus(live, { state: "read", paths: [], partial: true, removed: [], codeUnread: false })).toBe("Partly read");
  });

  it("says when the live build still requests a route the code removed", () => {
    const shadow = { state: "read" as const, paths: ["/api/legacy/export"], partial: false, removed: ["/api/legacy/export"], codeUnread: false };
    const out = html({ live, repository: "acme/app", shadow });
    expect(out).toContain("Removed from acme/app, still live.");
    expect(out).toMatch(/older than your code/);
    expect(liveSiteStatus(live, shadow)).toBe("1 removed from code, still live");
  });

  it("says when the audit left files unread, so a listed address may be a route it never saw", () => {
    const out = html({ live, repository: "acme/app", shadow: { state: "read", paths: ["/api/x"], partial: false, removed: [], codeUnread: true } });
    expect(out).toMatch(/did not read every file/);
  });

  it("says what the live site started and stopped requesting since the last read", () => {
    const changed = { ...live, change: { comparable: true as const, since: "2026-10-19T09:00:00.000Z", added: ["/api/export"], removed: ["/api/old"] } };
    const out = html({ live: changed, repository: "acme/app", shadow: { state: "read", paths: [], partial: false, removed: [], codeUnread: false } });
    expect(out).toContain("Since 2026-10-19 09:00 UTC");
    expect(out).toContain("/api/export");
    expect(out).toContain("/api/old");
    const same = html({ live: { ...live, change: { comparable: true, since: "x", added: [], removed: [] } }, repository: "acme/app",
      shadow: { state: "read", paths: [], partial: false, removed: [], codeUnread: false } });
    expect(same).not.toMatch(/Since/);
  });

  it("names addresses another selected repository serves, outside the not checked list", () => {
    const out = html({ live, repository: "acme/web", shadow: { state: "read", paths: [], partial: false, removed: [], codeUnread: false,
      servedElsewhere: [{ path: "/api/billing/7", repository: "acme/api" }] } });
    expect(out).toContain("Served by another repository you selected");
    expect(out).toContain("(acme/api)");
  });

  it("offers the binding when no address is bound", () => {
    const out = html({ live: null, repository: null, shadow: { state: "unknown", why: "No app address is bound to this repository." } });
    expect(out).toContain("/dashboard/settings");
    expect(liveSiteStatus(null, { state: "unknown", why: "x" })).toBe("Not bound");
  });

  it("uses no dashes in its copy", () => {
    const out = html({ live, repository: "acme/app", shadow: { state: "read", paths: [], partial: false, removed: [], codeUnread: false } });
    expect(out.replace(/<[^>]+>/g, "")).not.toMatch(/ [-–—] /);
  });
});
