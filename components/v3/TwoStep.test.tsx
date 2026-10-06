import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("@/lib/supabaseBrowser", () => ({ getSupabaseBrowser: () => ({}) }));
import { MfaChallengeView, TwoStepView } from "./TwoStep";

// Two-step sign-in (Felipe 2026-10-06: make sign-in safe). The code field is
// labelled, numeric, fillable by the phone or a password manager, and paste is
// never blocked (WCAG 2.2 accessible authentication).
const noop = () => {};

describe("code step at sign-in", () => {
  const one = [{ id: "f1", name: "ShipLock" }];
  const html = renderToStaticMarkup(<MfaChallengeView state="ready" code="" error={null} factors={one} factorId="f1" onFactor={noop} onCode={noop} onSubmit={noop} />);
  it("labels a numeric one-time-code field and allows paste", () => {
    expect(html).toMatch(/<label[^>]*for="mfa-code"[^>]*>Code<\/label>/);
    expect(html).toMatch(/autoComplete="one-time-code"|autocomplete="one-time-code"/);
    expect(html).toMatch(/inputMode="numeric"|inputmode="numeric"/);
    expect(html).not.toMatch(/onpaste/i);
  });
  it("offers a way out", () => {
    expect(html).toContain("Sign out");
  });
  it("says plainly when the code was wrong, and when nothing could be loaded", () => {
    expect(renderToStaticMarkup(<MfaChallengeView state="ready" code="1" error="That code did not work." factors={one} factorId="f1" onFactor={noop} onCode={noop} onSubmit={noop} />))
      .toMatch(/role="alert"[^>]*>That code did not work\./);
    expect(renderToStaticMarkup(<MfaChallengeView state="unavailable" code="" error={null} factors={[]} factorId={null} onFactor={noop} onCode={noop} onSubmit={noop} />))
      .toContain("could not confirm your sign-in");
  });
  // Recovery without a support reset: with a backup authenticator, the
  // person picks which app to read the code from; with one, no choice shows.
  it("lets a person with a backup choose which authenticator to use", () => {
    expect(html).not.toContain("<fieldset");
    const two = renderToStaticMarkup(<MfaChallengeView state="ready" code="" error={null}
      factors={[{ id: "f1", name: "ShipLock" }, { id: "f2", name: "ShipLock backup" }]} factorId="f2" onFactor={noop} onCode={noop} onSubmit={noop} />);
    expect(two).toMatch(/<fieldset[^>]*>\s*<legend[^>]*>Authenticator<\/legend>/);
    expect(two).toMatch(/<input(?=[^>]*type="radio")(?=[^>]*value="f2")(?=[^>]*checked="")[^>]*>/);
    expect(two).not.toMatch(/<input(?=[^>]*value="f1")(?=[^>]*checked="")[^>]*>/);
    expect(two).toMatch(/<label[^>]*for="mfa-factor-f1"[^>]*>ShipLock<\/label>/);
  });
});

describe("two-step card in Settings", () => {
  const base = { code: "", error: null, busy: false, onCode: noop, onStart: noop, onConfirm: noop, onCancel: noop, onAskRemove: noop, onRemove: noop, onKeep: noop };
  const main = { id: "f1", name: "ShipLock", since: "2026-10-06T00:00:00Z" };
  const backup = { id: "f2", name: "ShipLock backup", since: "2026-10-07T00:00:00Z" };
  it("explains why to turn it on", () => {
    const html = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "off" }} />);
    expect(html).toContain("Turn on");
    expect(html).toMatch(/stolen password/);
  });
  it("shows the QR code with a text alternative and the setup key", () => {
    const html = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "enrolling", backup: false, factorId: "f", qr: "data:image/svg+xml;utf-8,<svg/>", secret: "ABCD EFGH" }} />);
    expect(html).toMatch(/<img[^>]*alt="QR code to add ShipLock to your authenticator app"/);
    expect(html).toContain("ABCD EFGH");
    expect(html).toContain("Confirm");
  });
  it("asks once more before turning it off", () => {
    expect(renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factors: [main], removing: null }} />)).toContain("Turn off");
    const confirm = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factors: [main], removing: "f1" }} />);
    expect(confirm).toContain("Keep it on");
    expect(confirm).toMatch(/role="group"/);
  });
  it("offers a backup authenticator until one exists, so a lost phone does not lock the account", () => {
    const one = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factors: [main], removing: null }} />);
    expect(one).toContain("Add a backup");
    expect(one).toMatch(/lose your phone/);
    const two = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factors: [main, backup], removing: null }} />);
    expect(two).not.toContain("Add a backup");
    expect(two).toContain("ShipLock backup");
    expect(two).toMatch(/aria-label="Remove ShipLock backup"/);
    expect(two).not.toContain("Turn off");
  });
  it("removes one of two authenticators without turning two-step sign-in off", () => {
    const confirm = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factors: [main, backup], removing: "f2" }} />);
    expect(confirm).toMatch(/role="group"[^>]*aria-label="Confirm removing ShipLock backup"/);
    expect(confirm).toContain("Keep it");
    expect(confirm).not.toContain("Turn off");
  });
  it("names the backup setup as a backup", () => {
    const html = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "enrolling", backup: true, factorId: "f", qr: "data:image/svg+xml;utf-8,<svg/>", secret: "K" }} />);
    expect(html).toMatch(/second phone or your password manager/);
  });
  it("uses no dashes", () => {
    for (const view of [{ state: "off" }, { state: "on", factors: [main], removing: null }, { state: "on", factors: [main, backup], removing: "f2" }] as const) {
      expect(renderToStaticMarkup(<TwoStepView {...base} view={view} />).replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]| - /);
    }
  });
});
