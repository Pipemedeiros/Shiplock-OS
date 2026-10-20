import { describe, expect, it } from "vitest";
import { surfaceChange } from "./surfaceChange";

// Watch for the outside view: what the live site started or stopped
// requesting since the last read of the same address. A change is claimed
// only between two complete reads; anything else is not comparable, never
// "no change".
const read = (requests: string[], over: Record<string, unknown> = {}) =>
  ({ url: "https://app.acme.com", complete: true, requests, recordedAt: "2026-10-20T09:00:00.000Z", ...over });

describe("surfaceChange", () => {
  it("lists backend addresses added and removed since the last complete read", () => {
    expect(surfaceChange(read(["/api/me", "/api/old", "/pricing"]), read(["/api/me", "/api/export", "/about"]).requests, true, "https://app.acme.com"))
      .toEqual({ comparable: true, since: "2026-10-20T09:00:00.000Z", added: ["/api/export"], removed: ["/api/old"] });
  });

  it.each([
    ["there is no earlier read", null, true],
    ["the earlier read was of another address", read([], { url: "https://old.acme.com" }), true],
    ["the earlier read predates requests", { url: "https://app.acme.com", complete: true, recordedAt: null }, true],
    ["the earlier read was partial", read([], { complete: false }), true],
    ["the earlier read never said whether it was complete", read([], { complete: undefined }), true],
    ["this read is partial", read([]), false],
  ])("is not comparable when %s", (_why, previous, complete) => {
    expect(surfaceChange(previous as never, ["/api/x"], complete as boolean, "https://app.acme.com")).toMatchObject({ comparable: false });
  });
});
