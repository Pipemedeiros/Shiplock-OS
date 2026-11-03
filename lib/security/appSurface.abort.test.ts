import { beforeEach, describe, expect, it, vi } from "vitest";

// Bundle and origin probes go through guardedFetch; the caller's
// signal must reach it alongside each probe's own timeout.
const guarded = vi.hoisted(() => vi.fn());
vi.mock("@/lib/security/ssrfGuard", async (original) => ({
  ...await original<typeof import("./ssrfGuard")>(), guardedFetch: guarded,
}));

import { auditShippedBundle } from "./bundleAudit";
import { fetchOriginHeaders } from "./originExposure";

beforeEach(() => {
  guarded.mockReset().mockImplementation(() => new Promise<Response>(() => {}));
});

describe("app-surface probe cancellation", () => {
  it.each([
    ["auditShippedBundle", (signal: AbortSignal) => auditShippedBundle("https://app.example.com", signal)],
    ["fetchOriginHeaders", (signal: AbortSignal) => fetchOriginHeaders("https://app.example.com", signal)],
  ])("%s forwards the caller signal to guardedFetch", async (_name, call) => {
    const caller = new AbortController();
    void call(caller.signal);
    await vi.waitFor(() => expect(guarded).toHaveBeenCalled());
    const signal = (guarded.mock.calls[0][1] as RequestInit).signal!;
    expect(signal.aborted).toBe(false);
    caller.abort(new Error("collector timed out"));
    expect(signal.aborted).toBe(true);
  });
});
