import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AppUrlView } from "./AppUrlPanel";

// G3: the outside view reads the founder's app only at an address they
// confirmed. Every state says what happens, and every press answers.
const base = { current: null, repository: null, repositories: [] as string[], otherNames: null as { name: string; lastIssued: string }[] | null, suggestions: [], busy: false, saved: false, error: "", onSave: () => {}, onClear: () => {} };
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

  // P5: the founder names the repository the address serves; live reach joins only there.
  it("shows which repository the address serves, and a labeled choice defaulting to the only one", () => {
    const t = text(renderToStaticMarkup(<AppUrlView {...base} current="https://acme.com" repository="acme/app" repositories={["acme/app"]} />));
    expect(t).toMatch(/ShipLock reads https:\/\/acme\.com for acme\/app/);
    const one = renderToStaticMarkup(<AppUrlView {...base} repositories={["acme/app"]} />);
    expect(one).toMatch(/<label[^>]*for="app-repo"/);
    expect(one).toMatch(/<option value="acme\/app" selected="">acme\/app<\/option>/);
    const two = renderToStaticMarkup(<AppUrlView {...base} repositories={["acme/app", "acme/web"]} />);
    expect(two).toMatch(/<option value="" selected="">None of these<\/option>/);
    expect(renderToStaticMarkup(<AppUrlView {...base} />)).not.toContain("app-repo");
  });

  // Certificate transparency: names under the founder's domain, for review only.
  it("lists other certificate names for review, says ShipLock does not read them, and says when there are none", () => {
    const names = Array.from({ length: 12 }, (_, i) => ({ name: `n${i}.acme.com`, lastIssued: "2026-09-01" }));
    const t = text(renderToStaticMarkup(<AppUrlView {...base} current="https://app.acme.com" otherNames={names} />));
    expect(t).toMatch(/Other addresses on your domain/);
    expect(t).toContain("n0.acme.com");
    expect(t).not.toContain("n11.acme.com");
    expect(t).toMatch(/and 2 more/);
    expect(t).toMatch(/ShipLock does not read them/);
    expect(t).not.toMatch(/[–—]/);
    expect(text(renderToStaticMarkup(<AppUrlView {...base} current="https://app.acme.com" otherNames={[]} />))).toMatch(/No other names under your domain/);
    expect(text(renderToStaticMarkup(<AppUrlView {...base} current="https://app.acme.com" />))).not.toMatch(/Other addresses/);
  });
});
