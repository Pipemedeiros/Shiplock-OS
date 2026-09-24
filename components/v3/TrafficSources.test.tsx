import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { TrafficSources } from "./TrafficSources";
import type { TrafficSourceStatus } from "@/lib/traffic/sourceStatus";

const s = (over: Partial<TrafficSourceStatus>): TrafficSourceStatus => ({ repositoryId: "r", repository: "acme/app", sites: 0,
  gateway: "not_connected", observedAt: null, hasSource: false, ...over });

describe("TrafficSources (Q3)", () => {
  it("renders every state, and says plainly when there is no source", () => {
    const html = renderToStaticMarkup(<TrafficSources sources={{ available: true, items: [
      s({ repositoryId: "a", gateway: "read", observedAt: "2026-09-23T10:00:00.000Z", hasSource: true }),
      s({ repositoryId: "b", gateway: "unread", observedAt: "2026-09-23T10:00:00.000Z" }),
      s({ repositoryId: "c", gateway: "unbound" }),
      s({ repositoryId: "d", gateway: "not_enabled" }),
      s({ repositoryId: "e", sites: 2, hasSource: true }),
      s({ repositoryId: "f" }),
      s({ repositoryId: "g", gateway: "never_read" }),
    ] }} />);
    expect(html).toContain("Supabase gateway log read 2026-09-23 10:00 UTC");
    expect(html).toContain("could not be read");
    expect(html).toContain("not linked to this repository");
    expect(html).toContain("not enabled for this account");
    expect(html).toContain("2 snippet sites");
    expect(html).toContain("No traffic source: ShipLock sees no traffic for this repository.");
    expect(html).toContain("not read yet");
    expect(html).not.toMatch(/quiet|clean|[–—]| - /i);
  });
  it("offers a rate-limit pull request under a repository with a matched hot route (Q12-4)", () => {
    const html = renderToStaticMarkup(<TrafficSources sources={{ available: true, items: [s({ repositoryId: "a", gateway: "read", observedAt: "2026-09-23T10:00:00.000Z", hasSource: true })] }}
      offers={{ a: [{ file: "app/api/orders/route.ts", pattern: "/api/orders", suspiciousRequests: 9 }] }} />);
    expect(html).toContain("Preview the pull request");
    expect(html).toContain("/api/orders: 9 suspicious requests");
  });
  it("says when nothing could be loaded, and when no repository is selected", () => {
    expect(renderToStaticMarkup(<TrafficSources sources={{ available: false, items: [] }} />)).toMatch(/could not load/i);
    expect(renderToStaticMarkup(<TrafficSources sources={{ available: true, items: [] }} />)).toMatch(/Select a repository/);
  });
});
