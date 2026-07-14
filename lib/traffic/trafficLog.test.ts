import { describe, expect, it } from "vitest";
import { deriveInstalled, INSTALL_ACTIVE_WINDOW_MS } from "./trafficLog";

describe("deriveInstalled", () => {
  const now = Date.parse("2026-07-14T12:00:00Z");

  it("is false when never seen", () => {
    expect(deriveInstalled(null, now)).toBe(false);
  });

  it("is true when seen within the active window", () => {
    const recent = new Date(now - INSTALL_ACTIVE_WINDOW_MS / 2).toISOString();
    expect(deriveInstalled(recent, now)).toBe(true);
  });

  it("is false when last seen is older than the active window", () => {
    const stale = new Date(now - INSTALL_ACTIVE_WINDOW_MS - 1000).toISOString();
    expect(deriveInstalled(stale, now)).toBe(false);
  });

  it("is false on an unparseable timestamp", () => {
    expect(deriveInstalled("not-a-date", now)).toBe(false);
  });
});
