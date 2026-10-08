import { describe, expect, it } from "vitest";
import { routesOmittedNote, withRoutesOmitted } from "./audit";

// Felipe 2026-10-08: every data route is paged to the customer's agent. A
// route that reached no page (the page bound, or a page the monthly limit
// stopped) is still said out loud, and the count follows what was offered.
describe("routes not reasoned over", () => {
  it("says nothing when every data route reached a page", () => {
    expect(routesOmittedNote(0, 0)).toBeNull();
  });

  it("replaces the planned count with what was actually offered", () => {
    const coverage = [{ name: "Attack reasoning", why: "w", effect: "e" }];
    const after = withRoutesOmitted(coverage, 61, 3);
    expect(after.map((n) => n.name)).toEqual(["Attack reasoning", "61 routes not reasoned over"]);
    expect(after[1].effect).toMatch(/3 of them/);
    expect(withRoutesOmitted(after, 1, 0).map((n) => n.name)).toEqual(["Attack reasoning", "1 route not reasoned over"]);
    expect(withRoutesOmitted(after, 0, 0).map((n) => n.name)).toEqual(["Attack reasoning"]);
    expect(JSON.stringify(after)).not.toMatch(/[–—]/);
  });
});
