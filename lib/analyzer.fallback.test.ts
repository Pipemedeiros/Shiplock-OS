import { describe, expect, it, vi } from "vitest";
import type { ScanResult } from "./scanner";

// 1E-3: the scan report must not warn about a check that never got a response.
import { analyzeResult } from "./analyzer";

const scan = (over: Partial<ScanResult>) => ({ tables: [], ...over }) as unknown as ScanResult;

describe("analyzer fallback ignores untested rate-limit checks", () => {
  it("omits both warnings when the probes got no response", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await analyzeResult(scan({
      botProtection: { tested: false, rateLimitHeadersPresent: false },
      secureAuth: { tested: false, loginRateLimited: false },
    }));
    log.mockRestore();
    const titles = result.issues.map((i) => i.title);
    expect(titles).not.toContain("No rate-limit headers in API responses");
    expect(titles).not.toContain("Login endpoint not rate limited");
  });
});

// 1E-5: a check that did not run is never reported as passed.
describe("analyzer honesty about unread checks", () => {
  it("does not claim every check passed when some could not be verified", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const result = await analyzeResult(scan({
      corsConfig: { tested: false, wildcardOrigin: false, allowOriginValue: null },
      massAssignment: { tested: false, results: [] },
    }));
    log.mockRestore();
    expect(result.summary).not.toMatch(/all checks passed/i);
    expect(result.issues).toEqual(expect.arrayContaining([expect.objectContaining({
      severity: "INFO", title: "2 checks could not be verified",
    })]));
  });
});
