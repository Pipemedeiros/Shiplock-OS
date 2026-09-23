import { describe, expect, it, vi } from "vitest";
import type { ScanResult } from "./scanner";

// 1E-3: the deterministic fallback report must not warn about a check that
// never got a response. The model client is mocked to fail; no API call is made.
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic {
    static APIError = class extends Error {};
    static APIConnectionTimeoutError = class extends Error {};
    static AuthenticationError = class extends Error {};
    static RateLimitError = class extends Error {};
    static InternalServerError = class extends Error {};
    messages = { create: async () => { throw new Error("offline"); } };
  }
  return { default: Anthropic };
});

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
