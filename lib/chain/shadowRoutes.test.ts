import { describe, expect, it } from "vitest";
import { shadowRoutes, shadowRoutesFromRuns } from "./shadowRoutes";
import type { LiveReach } from "./liveReach";

// Shadow routes (G3, the outside view): addresses the live site requests on
// its own origin that the bound repository declares no route for. Code alone
// cannot see them; they are listed as not checked, never as an issue.
const live = (requests: string[] | null, read = { pages: 3, scriptsSeen: 5, scriptsRead: 5 }): LiveReach =>
  ({ repositoryId: "r1", host: "app.acme.com", observedAt: "2026-10-20T09:00:00.000Z", paths: requests ?? [], requests, read });
const routes = ["/api/me", "/api/notes/[id]", "/api/orders/[id]/share", "/dashboard", "action:app/a.ts#save"].map((path) => ({ path }));

describe("shadowRoutes", () => {
  it("lists the backend addresses the live site requests that no route declares", () => {
    const out = shadowRoutes(live(["/api/me", "/api/notes/", "/api/legacy/export", "/api/billing", "/pricing"]), routes);
    expect(out).toEqual({ state: "read", paths: ["/api/billing", "/api/legacy/export"], partial: false, removed: [], codeUnread: false });
  });

  it("matches a dynamic route by its fixed prefix and a template prefix by the routes under it", () => {
    expect(shadowRoutes(live(["/api/notes/42", "/api/orders/"]), routes)).toMatchObject({ paths: [] });
  });

  it("treats a catch-all or a tRPC router as declaring everything under it", () => {
    expect(shadowRoutes(live(["/api/anything/at/all"]), [{ path: "/api/[...all]" }])).toMatchObject({ paths: [] });
    expect(shadowRoutes(live(["/api/trpc/user.me"]), [{ path: "trpc:server/router.ts#user.me" }])).toMatchObject({ paths: [] });
  });

  it("reads a duplicated route name the way the inventory writes it", () => {
    expect(shadowRoutes(live(["/api/me"]), [{ path: "apps/web:/api/me" }])).toMatchObject({ paths: [] });
  });

  it("says partial when scripts went unread, so a short list is not the whole list", () => {
    expect(shadowRoutes(live(["/api/billing"], { pages: 1, scriptsSeen: 30, scriptsRead: 24 }), routes))
      .toEqual({ state: "read", paths: ["/api/billing"], partial: true, removed: [], codeUnread: false });
  });

  it.each([
    ["nothing is bound", null, routes],
    ["the fact predates own-origin requests", live(null), routes],
    ["no audit stored route facts", live(["/api/billing"]), null],
    ["the stored routes may be truncated", live(["/api/billing"]), Array.from({ length: 400 }, (_, i) => ({ path: `/api/r${i}` }))],
  ])("is unknown when %s, never an empty list", (_why, reach, declared) => {
    expect(shadowRoutes(reach, declared)).toMatchObject({ state: "unknown" });
  });

  // Deploy drift: a route an earlier audit of this repository declared, gone
  // from the newest one, still requested by the live site. The deployed build
  // is older than the code (a fix merged but never deployed, a failed build).
  it("marks a shadow route an earlier audit declared as removed from the repository", () => {
    const earlier = [[...routes, { path: "/api/legacy/export" }], [{ path: "/api/billing/[id]" }]];
    const out = shadowRoutes(live(["/api/legacy/export", "/api/billing/7", "/api/new"]), routes, earlier);
    expect(out).toEqual({ state: "read", paths: ["/api/billing/7", "/api/legacy/export", "/api/new"], partial: false,
      removed: ["/api/billing/7", "/api/legacy/export"], codeUnread: false });
  });

  // A route inventory from an audit that skipped files may lack real routes,
  // so a listed address may be one it never saw: said, never hidden.
  it("reads the newest run's routes and earlier ones, and marks code the audit did not read", () => {
    const run = (fullName: string, paths: string[], coverage: string[] = []) =>
      ({ fullName, routeFacts: paths.map((path) => ({ path })), coverage: coverage.map((name) => ({ name })) });
    const runs = [run("acme/other", ["/api/x"]), run("acme/app", ["/api/me"], ["12 files we did not read"]),
      run("acme/app", ["/api/legacy"]), { fullName: "acme/app", routeFacts: null, coverage: [] }];
    expect(shadowRoutesFromRuns(live(["/api/me", "/api/legacy", "/api/x"]), runs, "acme/app"))
      .toEqual({ state: "read", paths: ["/api/legacy", "/api/x"], partial: false, removed: ["/api/legacy"], codeUnread: true });
    expect(shadowRoutesFromRuns(live(["/api/me"]), runs, "acme/none")).toMatchObject({ state: "unknown" });
  });
});
