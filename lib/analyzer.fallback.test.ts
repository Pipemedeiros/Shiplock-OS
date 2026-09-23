import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanResult } from "./scanner";

// 1E-3: the deterministic fallback report must not warn about a check that
// never got a response. The model client is mocked to fail; no API call is made.
const sdkCreate = vi.hoisted(() => vi.fn<(request: { system: string }) => Promise<never>>(async () => { throw new Error("offline"); }));
vi.mock("@anthropic-ai/sdk", () => {
  class Anthropic {
    static APIError = class extends Error {};
    static APIConnectionTimeoutError = class extends Error {};
    static AuthenticationError = class extends Error {};
    static RateLimitError = class extends Error {};
    static InternalServerError = class extends Error {};
    messages = { create: sdkCreate };
  }
  return { default: Anthropic };
});

import { analyzeResult } from "./analyzer";

beforeEach(() => { sdkCreate.mockClear(); process.env.SHIPLOCK_FUNDED_SCAN_REPORT = "true"; });

describe("the legacy scan report spends ShipLock's key only when explicitly on (3G-2)", () => {
  it("returns the deterministic report and makes no model call by default", async () => {
    delete process.env.SHIPLOCK_FUNDED_SCAN_REPORT;
    const result = await analyzeResult({ tables: [] } as unknown as ScanResult);
    expect(sdkCreate).not.toHaveBeenCalled();
    expect(result.issues).toBeDefined();
  });
});

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

// 1E-5: a check that did not run is never reported as passed, in the model
// prompt or in the deterministic fallback.
describe("analyzer honesty about unread checks", () => {
  it("never tells the model an untested check is good", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    await analyzeResult(scan({}));
    log.mockRestore();
    const system = sdkCreate.mock.calls.at(-1)![0].system;
    expect(system).not.toMatch(/tested: false\s*→\s*(GOOD|No (issue|finding))/i);
    expect(system).toContain("tested: false means the check did not run");
    expect(system).toContain("It is never a pass and never GOOD");
  });

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
