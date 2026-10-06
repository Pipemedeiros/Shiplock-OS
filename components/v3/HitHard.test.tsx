import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { HitHard } from "./HitHard";

describe("hit hard tag", () => {
  const html = renderToStaticMarkup(<HitHard hit={{ pattern: "/api/orders", suspiciousRequests: 2000 }} />);
  it("says the route is under heavy traffic, in words", () => {
    expect(html).toContain("Hit hard");
  });
  it("gives the evidence on hover and to screen readers", () => {
    expect(html).toMatch(/title="2,000 suspicious requests observed on \/api\/orders"/);
    expect(html).toMatch(/aria-label="Hit hard: 2,000 suspicious requests observed on \/api\/orders"/);
  });
});
