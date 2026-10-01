import { afterEach, describe, expect, it, vi } from "vitest";
import { shiplockFundedCallAllowed } from "./funding";

afterEach(() => { delete process.env.SHIPLOCK_FUNDED_NARRATIVES; delete process.env.SHIPLOCK_FUNDED_SCAN_REPORT; });

describe("ShipLock-funded model calls outside the first-scan credit (3G-2)", () => {
  it("are off unless Felipe explicitly turns one on", () => {
    expect(shiplockFundedCallAllowed("graph-narrative")).toBe(false);
    expect(shiplockFundedCallAllowed("scan-report")).toBe(false);
    process.env.SHIPLOCK_FUNDED_NARRATIVES = "1";
    expect(shiplockFundedCallAllowed("graph-narrative")).toBe(false);
    process.env.SHIPLOCK_FUNDED_NARRATIVES = "true";
    expect(shiplockFundedCallAllowed("graph-narrative")).toBe(true);
    expect(shiplockFundedCallAllowed("scan-report")).toBe(false);
    expect(shiplockFundedCallAllowed("proving")).toBe(false);
  });
});

it("all non-credit switches reject unset and nonliteral approvals", () => {
  for (const purpose of ["graph-narrative", "scan-report", "proving", "graph-defence"] as const) {
    for (const value of [undefined, "", "false", "1", "TRUE", "yes"]) {
      vi.stubEnv("SHIPLOCK_FUNDED_NARRATIVES", value);
      vi.stubEnv("SHIPLOCK_FUNDED_SCAN_REPORT", value);
      vi.stubEnv("SHIPLOCK_FUNDED_PROVING", value);
      vi.stubEnv("SHIPLOCK_FUNDED_DEFENCE", value);
      expect(shiplockFundedCallAllowed(purpose)).toBe(false);
    }
  }
  vi.stubEnv("SHIPLOCK_FUNDED_DEFENCE", "true");
  expect(shiplockFundedCallAllowed("graph-defence")).toBe(true);
  vi.unstubAllEnvs();
});
