import { describe, expect, it } from "vitest";
import { appRouteForPath, matchHotPaths } from "./routeMatch";

// Q12-1 / Step 11: which App Router route file an observed request path hits.
const files = [
  "app/api/orders/route.ts", "app/api/orders/[id]/route.ts", "src/app/api/files/[...path]/route.ts",
  "app/(marketing)/api/contact/route.js", "app/api/opt/[[...rest]]/route.ts", "app/page.tsx", "pages/api/legacy.ts",
];

describe("appRouteForPath", () => {
  it("prefers a static segment over a dynamic one", () => {
    expect(appRouteForPath("/api/orders", files)).toEqual({ file: "app/api/orders/route.ts", pattern: "/api/orders" });
    expect(appRouteForPath("/api/orders/42", files)).toEqual({ file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id" });
  });
  it("handles catch-all, optional catch-all and route groups, and ignores query and trailing slash", () => {
    expect(appRouteForPath("/api/files/a/b.png?x=1", files)?.file).toBe("src/app/api/files/[...path]/route.ts");
    expect(appRouteForPath("/api/files", files)).toBeNull();
    expect(appRouteForPath("/api/opt", files)?.file).toBe("app/api/opt/[[...rest]]/route.ts");
    expect(appRouteForPath("/api/contact/", files)?.file).toBe("app/(marketing)/api/contact/route.js");
  });
  it("never matches pages, Pages Router API files, or unknown paths", () => {
    expect(appRouteForPath("/", files)).toBeNull();
    expect(appRouteForPath("/api/legacy", files)).toBeNull();
    expect(appRouteForPath("/api/nope", files)).toBeNull();
  });
});

describe("matchHotPaths", () => {
  it("groups observed paths by route file and sums requests, busiest first", () => {
    expect(matchHotPaths([
      { path: "/api/orders/1", suspiciousRequests: 30 }, { path: "/api/orders/2", suspiciousRequests: 20 },
      { path: "/api/orders", suspiciousRequests: 60 }, { path: "/wp-login.php", suspiciousRequests: 99 },
    ], files)).toEqual({
      matched: [
        { file: "app/api/orders/route.ts", pattern: "/api/orders", suspiciousRequests: 60, paths: ["/api/orders"] },
        { file: "app/api/orders/[id]/route.ts", pattern: "/api/orders/:id", suspiciousRequests: 50, paths: ["/api/orders/1", "/api/orders/2"] },
      ],
      unmatched: ["/wp-login.php"],
    });
  });
});
