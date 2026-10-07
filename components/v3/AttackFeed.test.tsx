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

// A3 on the Overview: one line, the attack's real state, a link to watch it.
describe("AttackSummary", () => {
  it("counts the attack's outcomes in one line and links to Activity", async () => {
    const { AttackSummary } = await import("./AttackFeed");
    const html = renderToStaticMarkup(<AttackSummary feed={{ phase: "checking", proposed: 4, steps: [
      { entry: "/a", title: "a", state: "confirmed" }, { entry: "/b", title: "b", state: "refuted" },
      { entry: "/c", title: "c", state: "checking" }, { entry: "/d", title: "d", state: "checking" },
    ] }} />);
    expect(html.replace(/<[^>]+>/g, "")).toContain("Your agent proposed 4 attacks: 1 confirmed, 1 refuted, 2 being checked.");
    expect(html).toContain('href="/dashboard/activity"');
  });
  it("names waiting and no answer plainly, and shows nothing when no attack was offered", async () => {
    const { AttackSummary } = await import("./AttackFeed");
    expect(renderToStaticMarkup(<AttackSummary feed={{ phase: "waiting_for_agent", proposed: 0, steps: [] }} />)).toContain("Waiting for your agent");
    expect(renderToStaticMarkup(<AttackSummary feed={{ phase: "not_offered", proposed: 0, steps: [] }} />)).toBe("");
  });
});
