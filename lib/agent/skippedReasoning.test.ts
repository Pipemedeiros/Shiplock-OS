import { describe, expect, it } from "vitest";
import { buildCoverage } from "./audit";
import type { StackReport } from "./stack";

/**
 * A reasoning step that did not run must never look like one that ran and found
 * nothing.
 *
 * On 2026-09-08 ten `proposeAttacks` calls returned `skipped: true` with
 * `400 — "Your credit balance is too low to access the Anthropic API."` and the
 * harness reporting them printed ten clean zeros: `admitted=0, rejected=0,
 * unassessed=0, unmatched=0`. Indistinguishable from ten runs that reasoned
 * over the corpus and admitted nothing. Only the standing rule that any zero
 * gets its own diagnosis caught it.
 *
 * The same hole was in the product. `buildCoverage` was passed `!canReason` for
 * `reasoningSkipped` — the TIME-budget check — so a run with time to spare
 * whose model call then failed produced an audit with no reasoned findings and
 * no note saying why. That is the shape of the failure this whole file exists
 * to prevent: absent read as clean.
 */

const stack: StackReport = { tools: [], authUnknown: true, databaseUnknown: true } as unknown as StackReport;

/** The signature is positional; name the two that matter here. */
const coverage = (over: { reasoningSkipped?: boolean } = {}) =>
  buildCoverage(stack, false, 0, false, 0, 0, [], over.reasoningSkipped ?? false, false, [], false);

const names = (notes: { name: string }[]) => notes.map((n) => n.name).join(" | ");

describe("a reasoning step that did not run", () => {
  it("is disclosed when it was skipped", () => {
    const notes = coverage({ reasoningSkipped: true });
    expect(names(notes)).toMatch(/reason/i);
  });

  it("is not disclosed when it ran, so the note keeps its meaning", () => {
    const notes = coverage({ reasoningSkipped: false });
    // If this ever starts matching, the note has become boilerplate and stops
    // telling the customer anything.
    const reasoningNotes = notes.filter((n) => /did not reason|reasoning step (was )?skipped|never reasoned/i.test(`${n.name} ${n.why}`));
    expect(reasoningNotes).toEqual([]);
  });

  it("says plainly that the run is not a clean result", () => {
    const note = coverage({ reasoningSkipped: true }).find((n) => /reason/i.test(n.name));
    expect(note).toBeDefined();
    // The customer-facing half of the invariant: silence must not read as
    // safety. Whatever the wording, it has to deny cleanliness somewhere.
    expect(`${note!.why} ${note!.effect}`).toMatch(/means nothing|not (a )?clean|were not looked for|did not run/i);
  });
});
