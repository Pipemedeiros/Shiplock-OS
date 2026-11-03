import type { RouteFact } from "@/lib/graph/routeInventory";
import type { CoverageNote } from "./audit";

/**
 * THE UNASSESSED DISCLOSURE, DERIVED FROM THE FACT LAYER.
 *
 * "Absent is not clean" is the second design commitment of this codebase, and
 * the call-path work made it load-bearing: many routes now correctly reach no
 * table, or reach one behind a gate we could not read, instead of being
 * credited with facts they never had. Invisible is the right failure direction
 * and it is still silently unassessed unless something says so.
 *
 * This is computed from route facts and nothing else. An earlier version keyed
 * the disclosure off the guard's refusals, and in four runs of five the model
 * proposed nothing for a real vulnerability, so the customer saw neither a
 * finding nor a note. A disclosure conditional on model behaviour is not a
 * disclosure.
 *
 * Presented as proportion, reason breakdown and a named sample, leading rather
 * than trailing: a list of two hundred endpoints is not information. Reasons
 * are described by risk, in the customer's terms, never by field name.
 */

export interface UnassessedSummary {
  /** Routes that reach at least one table. */
  dataTouching: number;
  /** Of those, routes with an identity, scope or signature check we could not read. */
  unassessed: number;
  /** Routes that reach no table while importing something we could not follow. */
  dataUnreadable: number;
  reasons: { identity: number; scope: number; signature: number };
  /** Up to five named endpoints, the ones over the most tables first. */
  sample: string[];
}

/** Routes that touch data but could not be fully read, counted once by the
 * first reason: identity, scope or signature. */
export function summarizeUnassessed(routes: RouteFact[]): UnassessedSummary {
  const dataTouching = routes.filter((r) => r.tables.length > 0);
  const unassessed = dataTouching.filter((r) => !r.identityReadable || !r.ownershipReadable || !r.machineGateReadable);
  const dataUnreadable = routes.filter((r) => r.tables.length === 0 && !r.dataReadable);

  // Each route is counted once, under the first reason that applies: an
  // unreadable identity makes the scope unreadable too, so the identity is
  // the reason.
  const reasons = { identity: 0, scope: 0, signature: 0 };
  for (const r of unassessed) {
    if (!r.identityReadable) reasons.identity++;
    else if (!r.ownershipReadable) reasons.scope++;
    else reasons.signature++;
  }

  const sample = [...unassessed, ...dataUnreadable]
    .sort((a, b) => b.tables.length - a.tables.length || a.path.localeCompare(b.path))
    .slice(0, 5)
    .map((r) => r.path);

  return { dataTouching: dataTouching.length, unassessed: unassessed.length, dataUnreadable: dataUnreadable.length, reasons, sample };
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * The Coverage note, or null when every data-touching route was judged and
 * every route's data access was followed. Null is the only clean state.
 */
export function unassessedNote(routes: RouteFact[]): CoverageNote | null {
  const s = summarizeUnassessed(routes);
  if (s.unassessed === 0 && s.dataUnreadable === 0) return null;

  const parts: string[] = [];
  if (s.reasons.identity > 0) {
    parts.push(`on ${plural(s.reasons.identity, "endpoint")} the check that decides who is calling runs somewhere we could not follow`);
  }
  if (s.reasons.scope > 0) {
    parts.push(`on ${plural(s.reasons.scope, "endpoint")} we could not tell whether the query is narrowed to the caller`);
  }
  if (s.reasons.signature > 0) {
    parts.push(`on ${plural(s.reasons.signature, "endpoint")} a signature or shared-secret check sits in a helper we could not attribute`);
  }
  if (s.dataUnreadable > 0) {
    parts.push(`${plural(s.dataUnreadable, "endpoint")} reach no table we could see but import code we could not follow, so their data access is out of view`);
  }

  const share = s.dataTouching > 0 ? Math.round((100 * s.unassessed) / s.dataTouching) : 0;
  const headline =
    s.unassessed > 0
      ? `${s.unassessed} of ${s.dataTouching} endpoints that reach data could not be judged (${share}%)`
      : `${plural(s.dataUnreadable, "endpoint")} whose data access we could not follow`;

  return {
    name: headline,
    why: `${parts.join("; ")}. Among them: ${s.sample.join(", ")}.`,
    effect:
      "These are not confirmed safe. They are unexamined, and a real gap on one of them would look exactly like this. Nothing on this list was reported as a finding, because we do not report what we could not read.",
    upgrade: "Review these endpoints by hand, or connect your database so access rules can be read directly",
  };
}
