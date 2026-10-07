import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AttackFeedCard } from "./AttackFeed";

// A3 (Felipe 2026-10-07): the customer sees the attack happening, with its real
// state: what was tried, and what each attempt came to.
describe("AttackFeedCard", () => {
  it("lists each attack with its state in words as well as a glyph", () => {
    const html = renderToStaticMarkup(<AttackFeedCard feed={{ phase: "checking", proposed: 3, steps: [
      { entry: "/api/orders", title: "Any user reads every order", state: "confirmed" },
      { entry: "/api/users", title: "Anyone deletes a user", state: "refuted" },
      { entry: "/api/notes", title: "Edits any note", state: "checking" },
    ] }} />);
    expect(html).toContain("Your agent proposed 3 attacks");
    expect(html).toContain("Any user reads every order");
    for (const word of ["Confirmed", "Refuted", "Being checked"]) expect(html).toContain(word);
    expect(html).toContain('href="/dashboard/risks"');
    expect(html.replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]| - /);
  });

  it("says plainly when the agent has not picked the attack up, and never shows a bare spinner", () => {
    const html = renderToStaticMarkup(<AttackFeedCard feed={{ phase: "waiting_for_agent", proposed: 0, steps: [] }} />);
    expect(html).toContain("Waiting for your agent");
    expect(html).toContain("ShipLock cannot start it");
  });

  it("does not count anything when the agent did not answer", () => {
    expect(renderToStaticMarkup(<AttackFeedCard feed={{ phase: "agent_unavailable", proposed: 0, steps: [] }} />))
      .toContain("Nothing it might have found is counted");
  });
});
