import { describe, expect, it } from "vitest";
import { summariseExposure, type TableInventory } from "./model";


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

