import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import Landing from "./page";

// Felipe (2026-09-30): the landing said too much, hedged every line and talked
// down to the reader. It now states the product in technical, plain words,
// leads with the thesis (code is half the picture), and stays short. The truth
// guards are unchanged: approval boundary, unread coverage, nothing planned
// presented as shipped, no invented numbers.
const html = renderToStaticMarkup(<Landing />);
const text = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

describe("landing page", () => {
  it("states the approval boundary and what it could not read", () => {
    expect(text).toContain("never merges or deploys");
    expect(text).toMatch(/what it could not read/i);
  });

  it("leads with the thesis: code, live configuration and traffic together", () => {
    expect(text).toMatch(/code is half the picture/i);
    expect(text).toMatch(/2,000 times a minute/);
    expect(text).toMatch(/row polic/i);
  });

  it("presents nothing planned as shipped and invents no numbers", () => {
    for (const phrase of ["reproduce", "replica", "Every route handler", "follows each entry point", "read everything",
      "first audit takes a few minutes", "only after the change has been tested", "1,140 workspaces", "in development"]) {
      expect(text, phrase).not.toContain(phrase);
    }
  });

  it("is short and does not hedge every sentence", () => {
    const words = text.split(" ").length;
    expect(words, `words: ${words}`).toBeLessThan(520);
    expect((text.match(/\bsupported\b/gi) ?? []).length).toBeLessThanOrEqual(1);
    expect(text).not.toMatch(/not describing a threat model|nobody has time|not a shipped claim/i);
  });
});
