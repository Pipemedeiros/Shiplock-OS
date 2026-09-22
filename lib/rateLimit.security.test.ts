import { describe, it, expect } from "vitest";
import { NextRequest } from "next/server";

const { getClientIpHash } = await import("./rateLimit");

function req(headers: Record<string, string> = {}) {
  return new NextRequest("https://shiplock.dev/api/scan", { headers });
}

describe("getClientIpHash — never crashes or produces a predictable/empty hash on a hostile header", () => {
  it("hashes a completely absent IP to a stable non-empty value rather than throwing", () => {
    const hash = getClientIpHash(req());
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it("uses the LAST hop of x-forwarded-for (the nearest trusted proxy's observation), not the attacker-controlled first entry", () => {
    const attackerClaimed = getClientIpHash(req({ "x-forwarded-for": "1.2.3.4" }));
    const withProxyChain = getClientIpHash(req({ "x-forwarded-for": "1.2.3.4, 5.6.7.8, 9.9.9.9" }));
    const lastHopOnly = getClientIpHash(req({ "x-forwarded-for": "9.9.9.9" }));
    expect(withProxyChain).toBe(lastHopOnly);
    expect(withProxyChain).not.toBe(attackerClaimed);
  });

  it("a header stuffed with garbage/injection-shaped content still resolves to a deterministic hash, no throw", () => {
    expect(() =>
      getClientIpHash(req({ "x-forwarded-for": "'; DROP TABLE users; --, <script>alert(1)</script>" }))
    ).not.toThrow();
  });
});
