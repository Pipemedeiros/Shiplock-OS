import { describe, expect, it } from "vitest";
import { suggestAppUrl } from "./appUrl";

// The outside view (shipped bundle, exposed paths) runs only when ShipLock
// knows the app's address, and the GitHub first onboarding never asked for
// it. GitHub already carries a repository's homepage; it is offered as a
// suggestion the founder confirms, never used on its own.
describe("suggestAppUrl", () => {
  it("offers a deployed homepage as its origin", () => {
    expect(suggestAppUrl("https://app.acme.com/dashboard?x=1")).toBe("https://app.acme.com");
    expect(suggestAppUrl("https://acme.vercel.app")).toBe("https://acme.vercel.app");
  });
  it("adds https to a bare host", () => {
    expect(suggestAppUrl("acme.com")).toBe("https://acme.com");
  });
  it.each([null, "", "http://acme.com", "https://github.com/acme/app", "https://www.npmjs.com/package/x",
    "https://localhost:3000", "https://127.0.0.1", "https://acme.github.io.evil@10.0.0.1", "not a url at all", "ftp://acme.com"])(
    "offers nothing for %s", (value) => {
      expect(suggestAppUrl(value)).toBeNull();
    });
});
