import { REASONING_NOTE, type CoverageNote } from "@/lib/agent/audit";

/**
 * Item 0c: what became of an audit's attack reasoning after the audit wrote
 * its note. Read from that audit's own tasks (098), so the Overview, Coverage,
 * the loop and MCP all show the same state. Returns null while the audit's
 * note is still right (no task, or the agent has not answered yet).
 */
export type RunTask = { kind: string; status: string; expiresAt: string; result: unknown };

const n = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);
const NOT_LOOKED = "Committed credentials and dependency advisories were still checked. Attack paths were not looked for in this audit, so this run finding none means nothing.";

/** The Coverage note for attack reasoning: answered, still waiting or lost
 * pages, never silence. */
export function reasoningOutcomeNote(tasks: readonly RunTask[], now: number): Omit<CoverageNote, "name"> | null {
  // One reasoning task per page of the route inventory (2026-10-08).
  const pages = tasks.filter((t) => t.kind === "attack_reasoning");
  if (pages.length === 0) return null;
  const expired = (t: RunTask) => t.status === "pending" && Date.parse(t.expiresAt) <= now;
  const answeredPages = pages.filter((t) => t.status === "proposal_received");
  const waitingPages = pages.filter((t) => t.status === "pending" && !expired(t)).length;
  const lostPages = pages.length - answeredPages.length - waitingPages;
  if (answeredPages.length === 0) {
    if (waitingPages > 0) return null;
    if (pages.some(expired)) return { why: "Your agent did not answer before the task expired.", effect: NOT_LOOKED, upgrade: "Run the audit again" };
    return { why: "Your agent could not answer this audit's reasoning task.", effect: NOT_LOOKED, upgrade: "Run the audit again" };
  }
  const parts = answeredPages.length < pages.length
    ? ` ${answeredPages.length} of ${pages.length} parts of your route inventory have an answer so far`
      + `${lostPages > 0 ? `; ${lostPages} ${lostPages === 1 ? "was" : "were"} not answered` : ""}.`
    : "";
  const again = lostPages > 0 ? { upgrade: "Run the audit again" } : {};

  const results = answeredPages.map((t) => (t.result ?? {}) as { admitted?: unknown[]; rejected?: unknown });
  const admitted = results.reduce((sum, r) => sum + (Array.isArray(r.admitted) ? r.admitted.length : 0), 0);
  const proposed = admitted + results.reduce((sum, r) => sum + num(r.rejected), 0);
  if (admitted === 0) return {
    why: `Your agent reasoned over this audit; none of the ${n(proposed, "attack path")} it proposed passed ShipLock's checks.${parts}`,
    effect: "This is one agent's search, not proof that no attack path exists.", ...again,
  };

  const checks = tasks.filter((t) => t.kind === "attack_verification");
  const waiting = checks.filter((t) => t.status === "pending" && !expired(t)).length;
  const done = checks.filter((t) => t.status === "proposal_received").map((t) => (t.result ?? {}) as Record<string, unknown>);
  const proved = done.reduce((s, r) => s + num(r.confirmed), 0);
  const refuted = done.reduce((s, r) => s + num(r.refuted), 0);
  const undecided = done.reduce((s, r) => s + num(r.unverified), 0);
  const tally = `${proved} proved and shown as ${proved === 1 ? "an issue" : "issues"}, ${refuted} refuted, ${undecided} could not be decided`;
  if (waiting > 0) return {
    why: `Your agent proposed ${n(admitted, "attack path")} that passed ShipLock's checks; ${n(waiting, "verification task")} ${waiting === 1 ? "waits" : "wait"} for your agent.${parts}`,
    effect: `Only claims proved by quoted lines become issues. So far: ${tally}.`, ...again,
  };
  return {
    why: `Your agent's ${n(admitted, "attack path")} ${admitted === 1 ? "was" : "were"} checked against quoted lines of your code: ${tally}.${parts}`,
    effect: "Only proved claims are issues. This is one agent's search, not proof that no other attack path exists.", ...again,
  };
}

/** A run's coverage with its reasoning note brought up to date. */
export function withReasoningOutcome(coverage: CoverageNote[], tasks: readonly RunTask[], now: number): CoverageNote[] {
  const outcome = reasoningOutcomeNote(tasks, now);
  if (!outcome) return coverage;
  return coverage.map((note) => (note.name === REASONING_NOTE ? { name: note.name, ...outcome } : note));
}
