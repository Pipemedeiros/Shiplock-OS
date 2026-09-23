import { describe, expect, it } from "vitest";
import type { ScanResult } from "@/lib/scanner";
import { extractFindings } from "./findings";

// 1E-3: a probe that never got an answer must not become a finding.
const scan = (over: Partial<ScanResult>) => ({ tables: [], ...over }) as unknown as ScanResult;

describe("extractFindings ignores untested rate-limit checks", () => {
  it("does not report missing rate-limit headers when the bot probe failed", () => {
    const ids = extractFindings(scan({ botProtection: { tested: false, rateLimitHeadersPresent: false } })).map((f) => f.id);
    expect(ids).not.toContain("no_rate_limit_headers");
  });

  it("does not report an unthrottled login when no login probe got a response", () => {
    const ids = extractFindings(scan({ secureAuth: { tested: false, loginRateLimited: false } })).map((f) => f.id);
    expect(ids).not.toContain("login_not_rate_limited");
  });

  it("still reports both when the probes actually ran", () => {
    const ids = extractFindings(scan({
      botProtection: { tested: true, rateLimitHeadersPresent: false },
      secureAuth: { tested: true, loginRateLimited: false },
    })).map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(["no_rate_limit_headers", "login_not_rate_limited"]));
  });
});
