import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Found on ShipLock itself (2026-09-29): proxy.ts sends a per-request nonce CSP with
// 'strict-dynamic'. A prerendered page has no nonce on its scripts, so the
// browser blocked all 28 of them on the live landing page and it never
// hydrated. Next only injects the nonce when a page renders per request, so
// the root layout opts every page into that.
describe("root layout", () => {
  const source = readFileSync("app/layout.tsx", "utf8");

  it("renders every page per request so the CSP nonce reaches its scripts", () => {
    expect(source).toMatch(/import \{ connection \} from "next\/server"/);
    expect(source).toMatch(/export default async function RootLayout/);
    expect(source).toMatch(/await connection\(\)/);
  });
});
