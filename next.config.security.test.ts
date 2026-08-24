import { describe, it, expect } from "vitest";
import nextConfig from "./next.config";

// Locks in the static security headers from next.config.ts. CSP itself is
// generated per-request in middleware.ts (needs a live nonce) and isn't
// covered here — this guards the headers that CAN be static.
describe("next.config.ts — baseline security headers are present on every path", () => {
  it("sends nosniff, frame-deny, and a safe referrer policy on every route", async () => {
    expect(nextConfig.headers).toBeDefined();
    const rules = await nextConfig.headers!();
    const catchAll = rules.find((r) => r.source === "/:path*");
    expect(catchAll).toBeDefined();

    const byKey = Object.fromEntries((catchAll!.headers ?? []).map((h) => [h.key, h.value]));
    expect(byKey["X-Content-Type-Options"]).toBe("nosniff");
    expect(byKey["X-Frame-Options"]).toBe("DENY");
    expect(byKey["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
  });

  it("does not advertise the framework via X-Powered-By", () => {
    expect(nextConfig.poweredByHeader).toBe(false);
  });
});
