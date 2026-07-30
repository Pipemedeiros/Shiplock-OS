import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { summariseExposure, type TableInventory } from "./model";

// §13.5 guardrail 5 makes PRESENTATION part of this feature's safety, so the
// rendering rules are asserted rather than left to whoever edits the copy next.
const RAW = readFileSync("components/d/ExposurePanel.tsx", "utf8");
// Comments are stripped before asserting: the module's own header DESCRIBES the
// prohibitions ("no red, no pulsing, no act now"), and matching that would fail
// the file for documenting the rule it follows.
const PANEL = RAW.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:'"`])\/\/[^\n]*/g, "$1");

const inventory: TableInventory[] = [
  {
    table: "profiles",
    categories: [{ category: "contact", label: "contact details", columns: ["email"] }],
    unclassifiedColumns: 2,
    rowCount: 4231,
  },
  {
    table: "messages",
    categories: [{ category: "content", label: "private content", columns: ["body"] }],
    unclassifiedColumns: 1,
    rowCount: null,
  },
];

describe("what the panel is given", () => {
  it("shows the arithmetic alongside the number", () => {
    const s = summariseExposure(inventory);
    expect(s.estimates[0].arithmetic).toContain("4,231 rows");
    expect(s.estimates[0].arithmetic).toContain("IBM");
  });

  // The total must never read as complete.
  it("names the table it could not count", () => {
    expect(summariseExposure(inventory).uncountedTables).toEqual(["messages"]);
  });

  it("totals only measured rows", () => {
    expect(summariseExposure(inventory).totalRecords).toBe(4231);
  });
});

describe("presentation guardrails", () => {
  // Guardrail 5: no urgency theatre. The number is frightening enough calmly.
  it("uses no alarm colour, pulsing or countdown", () => {
    expect(PANEL).not.toMatch(/#(ef4444|dc2626|ff0000)|\bred\b|pulse|countdown|animate/i);
  });

  it("never uses the language of litigation or urgency", () => {
    expect(PANEL).not.toMatch(/you will be sued|act now|immediately at risk|urgent/i);
  });

  // Guardrails 2 and 3.
  it("renders the arithmetic and cites the source inline", () => {
    expect(PANEL).toContain("e.arithmetic");
    expect(PANEL).toContain("SOURCES.perRecord.source");
  });

  // Guardrail 1: the caveat cannot be separated from the number.
  it("renders the caveat with the figure rather than as a footnote", () => {
    expect(PANEL).toContain("estimates[0].caveat");
  });

  // Guardrail 4: structure only, never a number for this customer.
  it("renders the regulatory note", () => {
    expect(PANEL).toContain("regulatoryNote");
  });

  // Guardrail 6: "we have not looked" must never render as a number.
  it("renders nothing at all when there is no measured exposure", () => {
    expect(PANEL).toMatch(/if \(!summary \|\| summary\.estimates\.length === 0\) return null/);
  });

  it("names the uncounted tables in the UI", () => {
    expect(PANEL).toContain("uncountedTables");
    expect(PANEL).toContain("we do not estimate them");
  });
});
