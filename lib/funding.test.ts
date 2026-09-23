import { afterEach, describe, expect, it } from "vitest";
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
  });
});
