import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { TrafficSitesView } from "./TrafficSites";

const base = { enabled: true, repositories: [{ id: "r1", fullName: "acme/app" }], sites: [], created: null, busy: false, error: "",
  onCreate: vi.fn(), onRevoke: vi.fn() };
const html = (props: Partial<Parameters<typeof TrafficSitesView>[0]> = {}) => renderToStaticMarkup(TrafficSitesView({ ...base, ...props }));

describe("TrafficSites (2F-2b)", () => {
  it("states the privacy contract and that the app never depends on ShipLock", () => {
    const out = html();
    expect(out).toContain("never request bodies, credentials, or your users");
    expect(out).toContain("never goes through ShipLock");
    expect(out).toContain("If ShipLock is down, your app is unaffected");
    expect(out).toContain("acme/app");
  });

  it("shows a new site's snippet once, and lists sites without tokens", () => {
    const withSnippet = html({ created: { host: "app.example.com", snippets: { nextjs: "SNIPPET-NEXT", web: "SNIPPET-WEB", express: "SNIPPET-EXPRESS" } } });
    expect(withSnippet).toContain("SNIPPET-NEXT");
    expect(withSnippet).toContain("shown only once");
    const listed = html({ sites: [{ siteId: "s1", host: "app.example.com", repository: "acme/app", createdAt: "2026-09-23T00:00:00Z" }] });
    expect(listed).toContain("app.example.com");
    expect(listed).toContain("Revoke");
  });

  it("says plainly when traffic is not enabled, and offers no site creation", () => {
    const out = html({ enabled: false });
    expect(out).toContain("not enabled for this account yet");
    expect(out).not.toContain("Add site");
  });
});
