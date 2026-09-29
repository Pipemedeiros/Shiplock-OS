import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ConsentBannerView, readConsent, writeConsent } from "./CookieConsent";

// Felipe (2026-09-29): cookies only with the visitor's choice, and a real way
// to reject. Analytics (PostHog) starts only after "accepted"; sign-in cookies
// are strictly necessary and need no consent.
const memory = () => {
  const map = new Map<string, string>();
  return { getItem: (k: string) => map.get(k) ?? null, setItem: (k: string, v: string) => void map.set(k, v) };
};

describe("cookie consent", () => {
  it("has no choice until the visitor makes one, then remembers it", () => {
    const store = memory();
    expect(readConsent(store)).toBeNull();
    writeConsent(store, "rejected");
    expect(readConsent(store)).toBe("rejected");
    writeConsent(store, "accepted");
    expect(readConsent(store)).toBe("accepted");
  });

  it("treats unreadable storage or an unknown value as no choice", () => {
    expect(readConsent({ getItem: () => { throw new Error("blocked"); }, setItem: () => {} })).toBeNull();
    const store = memory();
    store.setItem("shiplock_consent", "maybe");
    expect(readConsent(store)).toBeNull();
  });

  it("offers accept and reject with equal weight, and links the privacy policy", () => {
    const html = renderToStaticMarkup(<ConsentBannerView onAccept={() => {}} onReject={() => {}} />);
    expect(html).toContain(">Accept<");
    expect(html).toContain(">Reject<");
    expect(html.match(/<button/g)).toHaveLength(2);
    expect(html).toContain('href="/privacy"');
    expect(html.replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]/);
  });
});
