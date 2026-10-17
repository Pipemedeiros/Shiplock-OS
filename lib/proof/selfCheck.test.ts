import { describe, expect, it } from "vitest";
import { NO_SUCH_ID, checkMethods, selfCheck, readSelfCheck } from "./selfCheck";

// Strix's idea (proof per finding), rebuilt so ShipLock never sends attack
// traffic: the founder or their agent runs one request against their own
// local or preview app. It names an id that cannot exist, so it reads and
// changes nothing; the status code alone shows whether a check ran first.
const finding = (entry: string, attackClass = "missing_authentication", methods?: string[]) => ({ entry, attackClass, methods });

describe("selfCheck", () => {
  it("writes a request for a route that answers without a sign-in check", () => {
    expect(selfCheck(finding("/api/orders/[id]", "missing_authentication", ["DELETE"]))).toEqual({
      method: "DELETE",
      path: `/api/orders/${NO_SUCH_ID}`,
      curl: `curl -i -X DELETE "$APP_URL/api/orders/${NO_SUCH_ID}"`,
      reading: "Run it against your local or preview app, never production. A 401 or 403 means a sign-in check ran first. A 404 or a 200 means the route reached your data layer without one. A 405 means the route has no handler for that method; try the one it serves. The id does not exist, so nothing is read or changed.",
    });
  });

  it("fills catch-all and colon parameters and prefers a read over a write", () => {
    expect(selfCheck(finding("/api/files/[...path]", "missing_authentication", ["GET", "DELETE"]))?.curl)
      .toBe(`curl -i -X GET "$APP_URL/api/files/${NO_SUCH_ID}"`);
    expect(selfCheck(finding("/api/teams/:teamId/members", "missing_authentication"))?.path).toBe(`/api/teams/${NO_SUCH_ID}/members`);
  });

  it("offers nothing where one anonymous request cannot show the gap", () => {
    expect(selfCheck(finding("/api/orders/[id]", "missing_authorization"))).toBeNull();
    expect(selfCheck(finding("action:app/actions.ts#deleteNote"))).toBeNull();
    expect(selfCheck(finding("trpc:server/router.ts#post.delete"))).toBeNull();
    expect(selfCheck(finding("/api/orders"))).toBeNull();
  });

  it("speaks without dashes", () => {
    expect(selfCheck(finding("/api/orders/[id]"))!.reading).not.toMatch(/[–—]/);
  });
});

// The customer's agent reports the status it got (MCP report_self_check).
// Untrusted agent output: it says what the test showed, never that it proved.
describe("readSelfCheck", () => {
  it.each([
    [401, "check_ran"], [403, "check_ran"], [302, "redirected"], [307, "redirected"],
    [404, "reached"], [200, "reached"], [204, "reached"], [405, "wrong_method"], [500, "inconclusive"], [429, "inconclusive"],
  ] as const)("reads %i as %s", (status, outcome) => {
    expect(readSelfCheck(status).outcome).toBe(outcome);
  });

  it("says each reading in plain words, without dashes, and never claims proof", () => {
    for (const status of [401, 302, 404, 405, 500]) {
      const { meaning } = readSelfCheck(status);
      expect(meaning).not.toMatch(/[–—]/);
      expect(meaning).not.toMatch(/proven|proved|confirmed/i);
    }
  });
});

// The method comes from the audit's route facts: the methods that never
// refuse an anonymous caller first, then the methods the file exports.
describe("checkMethods", () => {
  it("prefers the methods that reach data without a sign-in check", () => {
    expect(checkMethods({ methods: ["GET", "POST"], unrefusedMethods: ["POST"] })).toEqual(["POST"]);
    expect(selfCheck({ entry: "/api/orders/[id]", attackClass: "missing_authentication",
      methods: checkMethods({ methods: ["GET", "DELETE"], unrefusedMethods: ["DELETE"] }) })!.curl).toBe(
      `curl -i -X DELETE "$APP_URL/api/orders/${NO_SUCH_ID}"`);
  });

  it("falls back to the exported methods, then to nothing (GET), for older facts", () => {
    expect(checkMethods({ methods: ["POST"] })).toEqual(["POST"]);
    expect(checkMethods({})).toEqual([]);
    expect(checkMethods(undefined)).toEqual([]);
  });
});
