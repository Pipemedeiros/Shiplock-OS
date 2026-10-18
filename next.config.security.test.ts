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
    // Powerful browser features ShipLock never uses are off for every page.
    expect(byKey["Permissions-Policy"]).toBe("camera=(), microphone=(), geolocation=(), browsing-topics=()");
  });

  // RFC 9116: a security product says where to report a vulnerability.
  it("publishes security.txt with a contact and a future expiry", async () => {
    const { readFileSync } = await import("node:fs");
    const txt = readFileSync("public/.well-known/security.txt", "utf8");
    expect(txt).toMatch(/^Contact: mailto:support@shiplock\.dev$/m);
    const expires = txt.match(/^Expires: (\S+)$/m)?.[1];
    expect(expires && Date.parse(expires) > Date.now()).toBe(true);
    expect(txt).toMatch(/^Canonical: https:\/\/shiplock\.dev\/\.well-known\/security\.txt$/m);
  });

  it("does not advertise the framework via X-Powered-By", () => {
    expect(nextConfig.poweredByHeader).toBe(false);
  });
});
