import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RateLimitOffers } from "./RateLimitButton";

describe("RateLimitOffers", () => {
  it("offers one clicked PR per hot route, saying it adds an off-by-default file", () => {
    const html = renderToStaticMarkup(<RateLimitOffers repositoryId="r1" offers={[
      { file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 50 }]} />);
    expect(html).toContain("/api/orders/:id");
    expect(html).toContain("50 suspicious requests");
    expect(html).toContain("Preview the pull request");
    expect(html).toMatch(/off until you turn it on/);
    expect(html).not.toMatch(/[–—]/);
  });
  it("renders nothing without offers", () => {
    expect(renderToStaticMarkup(<RateLimitOffers repositoryId="r1" offers={[]} />)).toBe("");
  });
});
