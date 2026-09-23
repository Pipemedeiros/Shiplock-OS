import { describe, expect, it } from "vitest";
import { crossSiteRefusal, isSameOrigin } from "./sameOrigin";

const req = (origin: string | null, headers: Record<string, string> = {}, url = "https://shiplock.dev/api/x") =>
  new Request(url, { method: "POST", headers: { ...(origin ? { origin } : {}), ...headers } });

describe("same-origin guard for cookie-authenticated mutations", () => {
  it("accepts the page's own origin", () => {
    expect(isSameOrigin(req("https://shiplock.dev"))).toBe(true);
  });

  it("accepts the configured public app origin when the internal URL differs, never a header's claim", () => {
    const internal = "http://localhost:3000/api/x";
    process.env.NEXT_PUBLIC_APP_URL = "https://shiplock.dev";
    expect(isSameOrigin(req("https://shiplock.dev", {}, internal))).toBe(true);
    expect(isSameOrigin(req("https://evil.example", { "x-forwarded-host": "evil.example", host: "evil.example" }, internal))).toBe(false);
  });

  it("refuses another site, a missing Origin, a scheme downgrade, and look-alike hosts", () => {
    expect(isSameOrigin(req("https://evil.example"))).toBe(false);
    expect(isSameOrigin(req(null))).toBe(false);
    expect(isSameOrigin(req("null"))).toBe(false);
    expect(isSameOrigin(req("http://shiplock.dev", { "x-forwarded-host": "shiplock.dev", "x-forwarded-proto": "https" }, "http://localhost:3000/x"))).toBe(false);
    expect(isSameOrigin(req("https://shiplock.dev.evil.example"))).toBe(false);
    expect(isSameOrigin(req("https://evil.example", { "x-forwarded-host": "evil.example" }))).toBe(false);
  });

  it("returns a 403 response only when refusing", async () => {
    expect(crossSiteRefusal(req("https://shiplock.dev"))).toBeNull();
    const refusal = crossSiteRefusal(req("https://evil.example"));
    expect(refusal?.status).toBe(403);
    expect(await refusal?.json()).toEqual({ error: "A same-origin request is required." });
  });
});
