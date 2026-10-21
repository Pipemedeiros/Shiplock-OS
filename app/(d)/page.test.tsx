import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import Landing from "./page";
import { MCP_TOOLS } from "@/lib/mcpTools";

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

  // Felipe 2026-10-21: the agent is the reader. The example session may only
  // name tools ShipLock serves, and it stops at the person's click.
  it("shows only real MCP tools in the agent session, ending at the customer's click", () => {
    const names = new Set(MCP_TOOLS.map((t) => t.name));
    const shown = [...text.matchAll(/shiplock · (\w+)/g)].map((m) => m[1]);
    expect(shown.length).toBeGreaterThan(2);
    for (const n of shown) expect(names.has(n), n).toBe(true);
    expect(text).not.toContain("open_fix_pull_request(");
    expect(text).toMatch(/one click, one receipt/);
  });
});
