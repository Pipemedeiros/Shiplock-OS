import { describe, expect, it } from "vitest";
import { reasoningOutcomeNote, withReasoningOutcome, type RunTask } from "./reasoningOutcome";

// The Coverage note about attack reasoning is written when
// the audit runs ("asked of your agent") and must follow what the agent and
// ShipLock's verification actually did afterwards. Never clean by omission.
const NOW = Date.parse("2026-10-06T12:00:00Z");
const later = "2026-10-07T00:00:00Z", earlier = "2026-10-05T00:00:00Z";
const reasoning = (status: string, result: unknown = null, expiresAt = later): RunTask =>
  ({ kind: "attack_reasoning", status, expiresAt, result });
const verify = (status: string, result: unknown = null, expiresAt = later): RunTask =>
  ({ kind: "attack_verification", status, expiresAt, result });

describe("reasoning outcome note", () => {
  it("leaves the audit's own note while the agent has not answered", () => {
    expect(reasoningOutcomeNote([], NOW)).toBeNull();
    expect(reasoningOutcomeNote([reasoning("pending")], NOW)).toBeNull();
  });

  it("says the agent did not answer in time", () => {
    const note = reasoningOutcomeNote([reasoning("pending", null, earlier)], NOW)!;
    expect(note.why).toMatch(/did not answer before the task expired/);
    expect(note.effect).toMatch(/not looked for/);
    expect(note.upgrade).toBe("Run the audit again");
  });

  it("says the agent could not answer", () => {
    expect(reasoningOutcomeNote([reasoning("unavailable")], NOW)!.why).toMatch(/could not answer/);
  });

  it("says no proposed path passed the checks, without calling the code clean", () => {
    const note = reasoningOutcomeNote([reasoning("proposal_received", { admitted: [], rejected: 4 })], NOW)!;
    expect(note.why).toMatch(/none of the 4 attack paths it proposed passed/);
    expect(note.effect).toMatch(/one agent's search, not proof/i);
  });

  it("counts verification still waiting on the agent", () => {
    const note = reasoningOutcomeNote([
      reasoning("proposal_received", { admitted: [{}, {}, {}], rejected: 1 }),
      verify("pending"), verify("proposal_received", { confirmed: 1, refuted: 0, unverified: 0 }),
    ], NOW)!;
    expect(note.why).toMatch(/1 verification task waits for your agent/);
  });

  it("reports what verification proved, refuted and could not decide", () => {
    const note = reasoningOutcomeNote([
      reasoning("proposal_received", { admitted: [{}, {}, {}], rejected: 0 }),
      verify("proposal_received", { confirmed: 1, refuted: 1, unverified: 0 }),
      verify("proposal_received", { confirmed: 0, refuted: 0, unverified: 1 }),
    ], NOW)!;
    expect(note.why).toMatch(/1 proved and shown as an issue, 1 refuted, 1 could not be decided/);
    expect(note.effect).not.toMatch(/\bsecure\b|\bsafe\b/);
  });

  it("uses no dashes", () => {
    for (const tasks of [[reasoning("unavailable")], [reasoning("proposal_received", { admitted: [], rejected: 0 })]]) {
      const note = reasoningOutcomeNote(tasks, NOW)!;
      expect(`${note.why} ${note.effect}`).not.toMatch(/[–—]| - /);
    }
  });
});

describe("applying the outcome to a run's coverage", () => {
  const notes = [{ name: "Reasoning about who can reach what", why: "asked", effect: "e" }, { name: "Other", why: "w", effect: "x" }];
  it("replaces only the reasoning note, keeping its name and place", () => {
    const out = withReasoningOutcome(notes, [reasoning("unavailable")], NOW);
    expect(out[0].name).toBe("Reasoning about who can reach what");
    expect(out[0].why).toMatch(/could not answer/);
    expect(out[1]).toEqual(notes[1]);
  });
  it("leaves coverage untouched when there is no outcome yet", () => {
    expect(withReasoningOutcome(notes, [reasoning("pending")], NOW)).toBe(notes);
  });
});

// Felipe 2026-10-08: every data route is paged to the agent, one task per
// page. The note sums every answered page and says which parts are still
// waiting or were never answered; one answered page is not the whole audit.
describe("reasoning outcome note across pages", () => {
  it("waits while every page waits, and sums answered pages", () => {
    expect(reasoningOutcomeNote([reasoning("pending"), reasoning("pending")], NOW)).toBeNull();
    const note = reasoningOutcomeNote([
      reasoning("proposal_received", { admitted: [{}], rejected: 1 }),
      reasoning("proposal_received", { admitted: [{}, {}], rejected: 0 }),
      verify("proposal_received", { confirmed: 2, refuted: 1, unverified: 0 }),
    ], NOW)!;
    expect(note.why).toMatch(/3 attack paths/);
    expect(note.why).not.toMatch(/parts of your route inventory/);
  });

  it("says when some parts are still waiting or were not answered", () => {
    const waiting = reasoningOutcomeNote([reasoning("proposal_received", { admitted: [], rejected: 2 }), reasoning("pending")], NOW)!;
    expect(waiting.why).toMatch(/1 of 2 parts of your route inventory have an answer so far/);
    const lost = reasoningOutcomeNote([reasoning("proposal_received", { admitted: [], rejected: 0 }), reasoning("pending", null, earlier)], NOW)!;
    expect(lost.why).toMatch(/1 was not answered/);
    expect(lost.upgrade).toBe("Run the audit again");
    expect(JSON.stringify([waiting, lost])).not.toMatch(/[–—]/);
  });

  it("says the agent did not answer only when no page was answered", () => {
    expect(reasoningOutcomeNote([reasoning("unavailable"), reasoning("pending", null, earlier)], NOW)!.why).toMatch(/did not answer|could not answer/);
  });
});
