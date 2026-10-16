/**
 * The ratchet of the self-improving loop (Karpathy's autoresearch: change one
 * thing, score it on a fixed budget, keep it only if the score rises),
 * applied to ShipLock's deterministic rules. A rule moves some findings to
 * To review; it is scored on labeled findings it never saw while being
 * written, against thresholds recorded before the run. Security is
 * asymmetric, so a rule that buys precision by moving real issues away is
 * rejected even when the headline number rises. The holdout is reached only
 * through Thresholdout (./thresholdout.ts). Pure: no I/O, no model.
 */
export type RuleRow = { truth: boolean; moved: boolean };
export type RuleScore = {
  labeled: number; tp: number; moved: number; movedTp: number; kept: number; keptTp: number;
  baselinePrecision: number | null; keptPrecision: number | null; movedPrecision: number | null;
};
export type KeepIf = { developmentPrecisionGainAtLeast: number; developmentTrueMovedToReviewAtMost: number };

const share = (a: number, b: number) => (b ? a / b : null);

export function scoreRule(rows: readonly RuleRow[]): RuleScore {
  let tp = 0, moved = 0, movedTp = 0;
  for (const r of rows) {
    if (r.truth) tp++;
    if (r.moved) { moved++; if (r.truth) movedTp++; }
  }
  const labeled = rows.length, kept = labeled - moved, keptTp = tp - movedTp;
  return { labeled, tp, moved, movedTp, kept, keptTp, baselinePrecision: share(tp, labeled),
    keptPrecision: share(keptTp, kept), movedPrecision: share(movedTp, moved) };
}

export function developmentVerdict(score: RuleScore, keepIf: KeepIf): { gain: number | null; trueMovedShare: number | null; passes: boolean } {
  const gain = score.keptPrecision !== null && score.baselinePrecision !== null ? score.keptPrecision - score.baselinePrecision : null;
  const trueMovedShare = share(score.movedTp, score.tp);
  const passes = gain !== null && trueMovedShare !== null
    && gain >= keepIf.developmentPrecisionGainAtLeast && trueMovedShare <= keepIf.developmentTrueMovedToReviewAtMost;
  return { gain, trueMovedShare, passes };
}
