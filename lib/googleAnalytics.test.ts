import { describe, expect, it } from "vitest";
import { startGoogleAnalytics } from "./googleAnalytics";

// Felipe 2026-10-12: Google Analytics on his business account, the way he
// monitors visitors. Same rule as PostHog: nothing loads before the visitor
// accepts analytics cookies, and nothing at all without a measurement id.
const fakeDom = () => {
  const appended: { src: string; async: boolean }[] = [];
  const doc = { createElement: () => ({ src: "", async: false }), head: { appendChild: (s: { src: string; async: boolean }) => void appended.push(s) } };
  const win: { dataLayer?: unknown[]; gtag?: (...args: unknown[]) => void } = {};
  return { doc, win, appended };
};

describe("startGoogleAnalytics", () => {
  it("loads gtag once for a valid measurement id and configures it without ad signals", () => {
    const { doc, win, appended } = fakeDom();
    expect(startGoogleAnalytics(doc, win, "G-ABC123XYZ")).toBe(true);
    expect(startGoogleAnalytics(doc, win, "G-ABC123XYZ")).toBe(false);
    expect(appended).toEqual([{ src: "https://www.googletagmanager.com/gtag/js?id=G-ABC123XYZ", async: true }]);
    const calls = (win.dataLayer ?? []).map((a) => Array.from(a as ArrayLike<unknown>));
    expect(calls[0][0]).toBe("js");
    expect(calls[1]).toEqual(["config", "G-ABC123XYZ", { allow_google_signals: false, allow_ad_personalization_signals: false }]);
  });

  it("does nothing without an id or with a malformed one", () => {
    for (const id of [undefined, "", "UA-123", "G-<script>", "G-abc lower"]) {
      const { doc, win, appended } = fakeDom();
      expect(startGoogleAnalytics(doc, win, id)).toBe(false);
      expect(appended).toEqual([]);
      expect(win.gtag).toBeUndefined();
    }
  });
});
