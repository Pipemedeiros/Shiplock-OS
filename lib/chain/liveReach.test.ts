import { describe, expect, it } from "vitest";
import { liveReachFrom } from "./liveReach";

// P5: a fact read from the live site joins a repository only through the
// founder's binding, for the address it was confirmed for, while that
// repository is selected and the fact was read from that same address.
const url = "https://app.acme.com";
const profile = { monitored_app_url: url, monitored_app_repository_id: "r1", monitored_app_bound_url: url };
const runtime = { appSurface: { url, scriptsSeen: 3, scriptsRead: 3, paths: ["/api/notes/"] },
  _evidence: { version: 1, fields: { appSurface: { recordedAt: "2026-10-17T10:00:00.000Z", completeness: "unknown" } } } };

describe("liveReachFrom", () => {
  it("admits the live paths under a current binding to a selected repository", () => {
    expect(liveReachFrom(profile, runtime, ["r1"])).toEqual({ repositoryId: "r1", host: "app.acme.com",
      observedAt: "2026-10-17T10:00:00.000Z", paths: ["/api/notes/"], requests: null,
      read: { pages: null, scriptsSeen: 3, scriptsRead: 3 }, change: null });
  });

  it("carries a well formed change and drops a malformed one", () => {
    const change = { comparable: true, since: "2026-10-19T09:00:00.000Z", added: ["/api/new"], removed: [] };
    expect(liveReachFrom(profile, { ...runtime, appSurface: { ...runtime.appSurface, change } }, ["r1"])?.change).toEqual(change);
    expect(liveReachFrom(profile, { ...runtime, appSurface: { ...runtime.appSurface, change: { comparable: true, added: ["https://x"] } } }, ["r1"])?.change).toBeNull();
  });

  it("carries the own-origin requests and pages read once the fact records them", () => {
    const v2 = { ...runtime, appSurface: { ...runtime.appSurface, pagesRead: 4, requests: ["/api/notes/", "https://evil.example/x"] } };
    expect(liveReachFrom(profile, v2, ["r1"])).toMatchObject({ requests: ["/api/notes/"], read: { pages: 4, scriptsSeen: 3, scriptsRead: 3 } });
  });

  it.each([
    ["no binding", { ...profile, monitored_app_repository_id: null, monitored_app_bound_url: null }, runtime, ["r1"]],
    ["the address changed after the confirm", { ...profile, monitored_app_url: "https://new.acme.com" }, runtime, ["r1"]],
    ["the repository is no longer selected", profile, runtime, ["r2"]],
    ["the fact was read from another address", profile, { ...runtime, appSurface: { ...runtime.appSurface, url: "https://old.acme.com" } }, ["r1"]],
    ["nothing was read yet", profile, { envVars: [] }, ["r1"]],
    ["a malformed fact", profile, { appSurface: { url, paths: "/api" } }, ["r1"]],
    ["no profile", null, runtime, ["r1"]],
  ])("joins nothing when %s", (_why, p, facts, selected) => {
    expect(liveReachFrom(p as typeof profile | null, facts, selected)).toBeNull();
  });

  it("keeps only plain paths from the stored fact", () => {
    const odd = { ...runtime, appSurface: { ...runtime.appSurface, paths: ["/api/ok", "https://evil.example/x", "/a b"] } };
    expect(liveReachFrom(profile, odd, ["r1"])?.paths).toEqual(["/api/ok"]);
  });
});
