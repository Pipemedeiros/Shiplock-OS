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

export function reasoningOutcomeNote(tasks: readonly RunTask[], now: number): Omit<CoverageNote, "name"> | null {
  const reasoning = tasks.find((t) => t.kind === "attack_reasoning");
  if (!reasoning) return null;
  const expired = (t: RunTask) => t.status === "pending" && Date.parse(t.expiresAt) <= now;
  if (expired(reasoning)) return { why: "Your agent did not answer before the task expired.", effect: NOT_LOOKED, upgrade: "Run the audit again" };
  if (reasoning.status === "unavailable") return { why: "Your agent could not answer this audit's reasoning task.", effect: NOT_LOOKED, upgrade: "Run the audit again" };
  if (reasoning.status !== "proposal_received") return null;

  const result = (reasoning.result ?? {}) as { admitted?: unknown[]; rejected?: unknown };
  const admitted = Array.isArray(result.admitted) ? result.admitted.length : 0;
  const proposed = admitted + num(result.rejected);
  if (admitted === 0) return {
    why: `Your agent reasoned over this audit; none of the ${n(proposed, "attack path")} it proposed passed ShipLock's checks.`,
    effect: "This is one agent's search, not proof that no attack path exists.",
  };

  const checks = tasks.filter((t) => t.kind === "attack_verification");
  const waiting = checks.filter((t) => t.status === "pending" && !expired(t)).length;
  const done = checks.filter((t) => t.status === "proposal_received").map((t) => (t.result ?? {}) as Record<string, unknown>);
  const proved = done.reduce((s, r) => s + num(r.confirmed), 0);
  const refuted = done.reduce((s, r) => s + num(r.refuted), 0);
  const undecided = done.reduce((s, r) => s + num(r.unverified), 0);
  const tally = `${proved} proved and shown as ${proved === 1 ? "an issue" : "issues"}, ${refuted} refuted, ${undecided} could not be decided`;
  if (waiting > 0) return {
    why: `Your agent proposed ${n(admitted, "attack path")} that passed ShipLock's checks; ${n(waiting, "verification task")} ${waiting === 1 ? "waits" : "wait"} for your agent.`,
    effect: `Only claims proved by quoted lines become issues. So far: ${tally}.`,
  };
  return {
    why: `Your agent's ${n(admitted, "attack path")} ${admitted === 1 ? "was" : "were"} checked against quoted lines of your code: ${tally}.`,
    effect: "Only proved claims are issues. This is one agent's search, not proof that no other attack path exists.",
  };
}

/** A run's coverage with its reasoning note brought up to date. */
export function withReasoningOutcome(coverage: CoverageNote[], tasks: readonly RunTask[], now: number): CoverageNote[] {
  const outcome = reasoningOutcomeNote(tasks, now);
  if (!outcome) return coverage;
  return coverage.map((note) => (note.name === REASONING_NOTE ? { name: note.name, ...outcome } : note));
}
