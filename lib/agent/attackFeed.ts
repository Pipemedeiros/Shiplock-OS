/**
 * The attack, as it happens (Felipe 2026-10-07: "the users should see the
 * agents requesting stuff, attacking, in a safe way they can see it doing
 * something"). Built only from the real state of the customer agent's tasks
 * for one audit: the reasoning task proposes attacks, verification tasks test
 * them against quoted lines. Pending is waiting, never done; an answer without
 * proof, or a check that expired, is "could not tell", never a verdict.
 */
export type AttackTask = {
  id: string; kind: string; status: string; expires_at?: string | null; result: unknown; context: unknown;
};
export type AttackStepState = "checking" | "confirmed" | "refuted" | "could_not_tell";
type AttackStep = { entry: string; title: string; state: AttackStepState };
export type AttackFeed = {
  phase: "not_offered" | "waiting_for_agent" | "agent_unavailable" | "checking" | "done";
  proposed: number;
  steps: AttackStep[];
};

const ANSWERED = "proposal_received";
type Proposal = { entry?: unknown; title?: unknown };
type Item = { id?: unknown; entry?: unknown; title?: unknown };
type Verdict = { id?: unknown; verdict?: unknown };

const arrayAt = (value: unknown, key: string): unknown[] => {
  const field = value && typeof value === "object" ? (value as Record<string, unknown>)[key] : undefined;
  return Array.isArray(field) ? field : [];
};
const expired = (t: AttackTask, now: number) => t.status === "pending" && Boolean(t.expires_at) && Date.parse(t.expires_at!) <= now;

/** What the Attack stage shows: whether the agent was offered work, is still
 * pending or offline, and the proposals it returned. */
export function attackFeed(tasks: readonly AttackTask[], now = Date.now()): AttackFeed {
  // One reasoning task per page of the route inventory (2026-10-08).
  const pages = tasks.filter((t) => t.kind === "attack_reasoning");
  if (pages.length === 0) return { phase: "not_offered", proposed: 0, steps: [] };
  const answered = pages.filter((t) => t.status === ANSWERED);
  const pageWaits = pages.some((t) => t.status === "pending" && !expired(t, now));
  if (answered.length === 0) return { phase: pageWaits ? "waiting_for_agent" : "agent_unavailable", proposed: 0, steps: [] };

  const proposals = answered.flatMap((page) => arrayAt(page.result, "admitted") as Proposal[])
    .filter((p) => typeof p.entry === "string" && typeof p.title === "string") as { entry: string; title: string }[];
  // Each proposal's state, from the verification task that tested it.
  const states = new Map<string, AttackStepState>();
  for (const task of tasks.filter((t) => t.kind === "attack_verification")) {
    const verdicts = new Map((arrayAt(task.result, "verdicts") as Verdict[]).map((v) => [String(v.id), String(v.verdict)]));
    for (const item of arrayAt(task.context, "items") as Item[]) {
      const key = `${String(item.entry)}\u0000${String(item.title)}`;
      const state: AttackStepState = task.status === "pending" && !expired(task, now) ? "checking"
        : task.status !== ANSWERED ? "could_not_tell"
          : verdicts.get(String(item.id)) === "confirmed" ? "confirmed"
            : verdicts.get(String(item.id)) === "refuted" ? "refuted" : "could_not_tell";
      states.set(key, state);
    }
  }
  const steps = proposals.map((p) => ({ entry: p.entry, title: p.title,
    state: states.get(`${p.entry}\u0000${p.title}`) ?? "could_not_tell" as AttackStepState }));
  return { phase: pageWaits || steps.some((s) => s.state === "checking") ? "checking" : "done", proposed: proposals.length, steps };
}
