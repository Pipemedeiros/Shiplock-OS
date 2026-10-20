import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ConfirmServesView } from "./ConfirmServes";

const html = (repositories: string[], extra: { busy?: boolean; error?: string } = {}) => renderToStaticMarkup(
  <ConfirmServesView url="https://acme.com" repositories={repositories} busy={extra.busy ?? false} error={extra.error ?? ""} onConfirm={() => {}} />);

describe("ConfirmServes (one click to join the live site)", () => {
  it("names the only repository on the button", () => {
    const out = html(["acme/app"]);
    expect(out).toContain("https://acme.com");
    expect(out).toContain("It serves acme/app");
    expect(out).not.toContain("<select");
  });

  it("offers a labelled choice when several repositories are selected", () => {
    const out = html(["acme/app", "acme/docs"]);
    expect(out).toMatch(/<label for="confirm-serves">Serves<\/label>/);
    expect(out).toContain('<option value="acme/docs">');
    expect(out).toContain(">Confirm<");
  });

  it("shows saving and errors, with no dashes", () => {
    expect(html(["acme/app"], { busy: true })).toContain("Saving");
    expect(html(["acme/app"], { error: "Choose one of the repositories you selected in ShipLock." })).toContain('role="alert"');
    expect(html(["acme/app"]).replace(/<[^>]+>/g, "")).not.toMatch(/ [-–—] /);
  });
});
