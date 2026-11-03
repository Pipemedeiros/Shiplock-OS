import { describe, expect, it } from "vitest";
import { attackFeed, type AttackTask } from "./attackFeed";

// Felipe 2026-10-07: "the users should see the agents requesting stuff,
// attacking, in a safe way they can see it doing something". The feed is the
// real state of the customer agent's tasks for an audit, never a show:
// pending is waiting, an answer without proof is "could not tell".
const now = Date.parse("2026-10-07T12:00:00Z");
const later = "2026-10-08T12:00:00Z", earlier = "2026-10-06T12:00:00Z";
const reasoning = (status: string, admitted: unknown[] = [], expires = later): AttackTask =>
  ({ id: "r", kind: "attack_reasoning", status, expires_at: expires, result: { admitted }, context: {} });
const verification = (status: string, items: unknown[], verdicts: unknown[] = [], expires = later): AttackTask =>
  ({ id: "v", kind: "attack_verification", status, expires_at: expires, result: { verdicts }, context: { items } });
const attack = (entry: string, title: string) => ({ entry, attackClass: "missing_authorization", title });

describe("attackFeed", () => {
  it("is not offered without a reasoning task, and waits while the agent has not answered", () => {
    expect(attackFeed([], now)).toEqual({ phase: "not_offered", proposed: 0, steps: [] });
    expect(attackFeed([reasoning("pending")], now).phase).toBe("waiting_for_agent");
  });

  it("says the agent did not answer when the task expired or was declined", () => {
    expect(attackFeed([reasoning("pending", [], earlier)], now).phase).toBe("agent_unavailable");
    expect(attackFeed([reasoning("unavailable")], now).phase).toBe("agent_unavailable");
  });

  it("follows each proposed attack to its verdict", () => {
    const a = attack("/api/orders", "Any user reads every order"), b = attack("/api/users", "Anyone deletes a user");
    const c = attack("/api/notes", "Signed-in user edits any note");
    const feed = attackFeed([
      reasoning("proposal_received", [a, b, c]),
      verification("proposal_received", [{ id: "0", entry: a.entry, title: a.title }, { id: "1", entry: b.entry, title: b.title }],
        [{ id: "0", verdict: "confirmed" }, { id: "1", verdict: "refuted" }]),
    ], now);
    expect(feed.phase).toBe("done");
    expect(feed.proposed).toBe(3);
    expect(feed.steps).toEqual([
      { entry: "/api/orders", title: "Any user reads every order", state: "confirmed" },
      { entry: "/api/users", title: "Anyone deletes a user", state: "refuted" },
      // No source could be listed for it, so nothing proved it either way.
      { entry: "/api/notes", title: "Signed-in user edits any note", state: "could_not_tell" },
    ]);
  });

  it("shows attacks being checked while their verification is pending", () => {
    const a = attack("/api/orders", "Any user reads every order");
    const feed = attackFeed([reasoning("proposal_received", [a]), verification("pending", [{ id: "0", entry: a.entry, title: a.title }])], now);
    expect(feed).toMatchObject({ phase: "checking", steps: [{ state: "checking" }] });
  });

  it("never turns an unanswered or unproven check into a verdict", () => {
    const a = attack("/api/orders", "Any user reads every order");
    expect(attackFeed([reasoning("proposal_received", [a]), verification("pending", [{ id: "0", entry: a.entry, title: a.title }], [], earlier)], now)
      .steps[0].state).toBe("could_not_tell");
    expect(attackFeed([reasoning("proposal_received", [a]), verification("proposal_received", [{ id: "0", entry: a.entry, title: a.title }],
      [{ id: "0", verdict: "unverified" }])], now).steps[0].state).toBe("could_not_tell");
  });
});

// Felipe 2026-10-08: one reasoning task per page of the route inventory.
describe("attackFeed across pages", () => {
  it("shows the attacks from every answered page and keeps checking while a page waits", () => {
    const a = attack("/api/orders", "Any user reads every order"), b = attack("/api/users", "Anyone deletes a user");
    const feed = attackFeed([reasoning("proposal_received", [a]), reasoning("proposal_received", [b]), reasoning("pending")], now);
    expect(feed.proposed).toBe(2);
    expect(feed.steps.map((s) => s.entry)).toEqual(["/api/orders", "/api/users"]);
    expect(feed.phase).toBe("checking");
    expect(attackFeed([reasoning("pending"), reasoning("unavailable")], now).phase).toBe("waiting_for_agent");
    expect(attackFeed([reasoning("unavailable"), reasoning("pending", [], earlier)], now).phase).toBe("agent_unavailable");
  });
});
