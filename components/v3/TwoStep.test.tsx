import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("@/lib/supabaseBrowser", () => ({ getSupabaseBrowser: () => ({}) }));
import { MfaChallengeView, TwoStepView } from "./TwoStep";

// Two-step sign-in (Felipe 2026-10-06: make sign-in safe). The code field is
// labelled, numeric, fillable by the phone or a password manager, and paste is
// never blocked (WCAG 2.2 accessible authentication).
const noop = () => {};

describe("code step at sign-in", () => {
  const html = renderToStaticMarkup(<MfaChallengeView state="ready" code="" error={null} onCode={noop} onSubmit={noop} />);
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
    expect(renderToStaticMarkup(<MfaChallengeView state="ready" code="1" error="That code did not work." onCode={noop} onSubmit={noop} />))
      .toMatch(/role="alert"[^>]*>That code did not work\./);
    expect(renderToStaticMarkup(<MfaChallengeView state="unavailable" code="" error={null} onCode={noop} onSubmit={noop} />))
      .toContain("could not confirm your sign-in");
  });
});

describe("two-step card in Settings", () => {
  const base = { code: "", error: null, busy: false, onCode: noop, onStart: noop, onConfirm: noop, onCancel: noop, onAskOff: noop, onOff: noop, onKeep: noop };
  it("explains why to turn it on", () => {
    const html = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "off" }} />);
    expect(html).toContain("Turn on");
    expect(html).toMatch(/stolen password/);
  });
  it("shows the QR code with a text alternative and the setup key", () => {
    const html = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "enrolling", factorId: "f", qr: "data:image/svg+xml;utf-8,<svg/>", secret: "ABCD EFGH" }} />);
    expect(html).toMatch(/<img[^>]*alt="QR code to add ShipLock to your authenticator app"/);
    expect(html).toContain("ABCD EFGH");
    expect(html).toContain("Confirm");
  });
  it("asks once more before turning it off", () => {
    expect(renderToStaticMarkup(<TwoStepView {...base} view={{ state: "on", factorId: "f", since: "2026-10-06T00:00:00Z" }} />)).toContain("Turn off");
    const confirm = renderToStaticMarkup(<TwoStepView {...base} view={{ state: "confirm_off", factorId: "f", since: "2026-10-06T00:00:00Z" }} />);
    expect(confirm).toContain("Keep it on");
    expect(confirm).toMatch(/role="group"/);
  });
  it("uses no dashes", () => {
    for (const view of [{ state: "off" }, { state: "on", factorId: "f", since: "2026-10-06T00:00:00Z" }] as const) {
      expect(renderToStaticMarkup(<TwoStepView {...base} view={view} />).replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]| - /);
    }
  });
});
