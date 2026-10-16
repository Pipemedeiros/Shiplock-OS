import { describe, expect, it } from "vitest";
import { developmentVerdict, scoreRule } from "./ratchet";

const rows = (spec: [truth: boolean, moved: boolean, count: number][]) =>
  spec.flatMap(([truth, moved, count]) => Array.from({ length: count }, () => ({ truth, moved })));
const keepIf = { developmentPrecisionGainAtLeast: 0.015, developmentTrueMovedToReviewAtMost: 0.03 };

describe("the ratchet: keep a rule only if it raises precision without moving real issues", () => {
  it("scores the kept and moved sets against the baseline", () => {
    const s = scoreRule(rows([[true, false, 90], [false, false, 5], [false, true, 5]]));
    expect(s).toMatchObject({ labeled: 100, tp: 90, moved: 5, movedTp: 0, kept: 95, keptTp: 90 });
    expect(s.baselinePrecision).toBeCloseTo(0.9);
    expect(s.keptPrecision).toBeCloseTo(90 / 95);
  });

  it("keeps a rule that moves only false findings", () => {
    const v = developmentVerdict(scoreRule(rows([[true, false, 90], [false, false, 5], [false, true, 5]])), keepIf);
    expect(v.passes).toBe(true);
  });

  it("rejects a rule that raises precision by moving real issues away", () => {
    const v = developmentVerdict(scoreRule(rows([[true, false, 80], [true, true, 10], [false, true, 10]])), keepIf);
    expect(v.trueMovedShare).toBeCloseTo(10 / 90);
    expect(v.passes).toBe(false);
  });

  it("rejects a rule whose gain is below noise", () => {
    const v = developmentVerdict(scoreRule(rows([[true, false, 90], [false, false, 9], [false, true, 1]])), keepIf);
    expect(v.passes).toBe(false);
  });

  it("reports precision as unavailable, never 100%, when nothing is labeled", () => {
    const s = scoreRule([]);
    expect(s.baselinePrecision).toBeNull();
    expect(developmentVerdict(s, keepIf).passes).toBe(false);
  });
});
