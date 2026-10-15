import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AppUrlView } from "./AppUrlPanel";

// G3: the outside view reads the founder's app only at an address they
// confirmed. Every state says what happens, and every press answers.
const base = { current: null, suggestions: [], busy: false, saved: false, error: "", onSave: () => {}, onClear: () => {} };
const text = (html: string) => html.replace(/<[^>]+>/g, " ");

describe("AppUrlView", () => {
  it("offers GitHub's suggestion with its repository, and a labeled field", () => {
    const html = renderToStaticMarkup(<AppUrlView {...base} suggestions={[{ repository: "acme/app", url: "https://acme.com" }]} />);
    expect(html).toContain("https://acme.com");
    expect(html).toContain("acme/app");
    expect(html).toMatch(/<label[^>]*for="app-url"/);
    expect(text(html)).toMatch(/Use this address/);
  });

  it("says what it reads and that it sends only what a visitor would", () => {
    const t = text(renderToStaticMarkup(<AppUrlView {...base} />));
    expect(t).toMatch(/JavaScript it ships/);
    expect(t).toMatch(/as any visitor would/);
    expect(t).toMatch(/not read/);
    expect(t).not.toMatch(/[–—]/);
  });

  it("shows the confirmed address with a way to stop", () => {
    const t = text(renderToStaticMarkup(<AppUrlView {...base} current="https://acme.com" />));
    expect(t).toMatch(/ShipLock reads https:\/\/acme\.com/);
    expect(t).toMatch(/Stop reading it/);
  });

  it("answers a press at once: busy, then saved, and errors are announced", () => {
    const busy = renderToStaticMarkup(<AppUrlView {...base} busy />);
    expect(busy).toContain('aria-busy="true"');
    expect(busy).toContain("v3-spin");
    expect(text(renderToStaticMarkup(<AppUrlView {...base} current="https://acme.com" saved />))).toMatch(/Saved\. Reading your app now/);
    expect(renderToStaticMarkup(<AppUrlView {...base} error="Enter your app's public https address." />)).toMatch(/role="alert"/);
  });
});
