import { describe, expect, it } from "vitest";
import { clopperPearsonLower, combineBatches, scoreBenchmark, type BenchFinding, type BenchLabel } from "./benchmark";

// Plan item H (Felipe 2026-10-06): "we can only launch when 90%+ precision,
// after all it is a security product". The gate is the recorded one
// (docs/evaluation/thresholds-release-2026-10.json); this module only counts.
const gate = { observedPrecisionAtLeast: 0.9, lowerBound95AtLeast: 0.85, minimumLabeledFindings: 100, repositoriesWithCorrectStatusAtLeast: 0.9 };
const yes = { accurate: "yes", real: "yes" } as const;
const no = { accurate: "no", real: "no" } as const;

function population(tp: number, fp: number, repos = 1): { findings: BenchFinding[]; labels: BenchLabel[] } {
  const findings: BenchFinding[] = [];
  const labels: BenchLabel[] = [];
  for (let i = 0; i < tp + fp; i++) {
    const f: BenchFinding = { repo: `r${i % repos}`, id: `f${i}`, severity: i % 2 ? "WARNING" : "CRITICAL", attackClass: "committed_secret" };
    findings.push(f);
    labels.push({ repo: f.repo, id: f.id, labelers: i < tp ? [yes, yes] : [no, no] });
  }
  return { findings, labels };
}

describe("clopperPearsonLower", () => {
  it("matches the exact one-sided bound the thresholds were written with", () => {
    expect(clopperPearsonLower(95, 100)).toBeCloseTo(0.898, 3);
    expect(clopperPearsonLower(90, 100)).toBeCloseTo(0.836, 3);
    expect(clopperPearsonLower(1, 1)).toBeCloseTo(0.05, 3);
    expect(clopperPearsonLower(0, 10)).toBe(0);
  });
});

describe("scoreBenchmark", () => {
  it("counts a true positive only when both labelers agree it is accurate and real", () => {
    const findings: BenchFinding[] = ["a", "b", "c", "d"].map((id) => ({ repo: "r", id, severity: "WARNING", attackClass: "x" }));
    const labels: BenchLabel[] = [
      { repo: "r", id: "a", labelers: [yes, yes] },
      { repo: "r", id: "b", labelers: [yes, no] },
      { repo: "r", id: "c", labelers: [{ accurate: "partly", real: "yes" }, yes] },
    ];
    const report = scoreBenchmark(findings, labels, gate);
    expect(report.statusSetting).toMatchObject({ n: 4, labeled: 3, tp: 1, fp: 2, unlabeled: 1 });
    expect(report.statusSetting.precision).toBeCloseTo(1 / 3, 6);
  });

  it("never reports 100% on nothing, and INFO does not set the status", () => {
    const report = scoreBenchmark([{ repo: "r", id: "i", severity: "INFO", attackClass: "x" }], [], gate);
    expect(report.statusSetting.precision).toBeNull();
    expect(report.repositories).toEqual([{ repo: "r", status: "no_open_issues", correct: null }]);
    expect(report.gate.result).toBe("not_measurable");
  });

  it("passes at 95 of 100 and fails at 90 of 100 on the lower bound", () => {
    const pass = population(95, 5, 10);
    expect(scoreBenchmark(pass.findings, pass.labels, gate).gate.result).toBe("pass");
    const fail = population(90, 10, 10);
    const report = scoreBenchmark(fail.findings, fail.labels, gate);
    expect(report.gate.result).toBe("fail");
    expect(report.gate.reasons.join(" ")).toMatch(/lower bound/);
  });

  it("is not measurable below 100 findings, with one labeler, or with an unlabeled status-setting finding", () => {
    const small = population(50, 0);
    expect(scoreBenchmark(small.findings, small.labels, gate).gate).toMatchObject({ result: "not_measurable" });
    const one = population(120, 0, 10);
    one.labels[0] = { ...one.labels[0], labelers: [yes] };
    expect(scoreBenchmark(one.findings, one.labels, gate).gate.reasons.join(" ")).toMatch(/two labelers/);
    // One labeler's yes is shown as provisional, never counted as true.
    const solo = population(3, 1);
    solo.labels = solo.labels.map((l) => ({ ...l, labelers: l.labelers.slice(0, 1) }));
    expect(scoreBenchmark(solo.findings, solo.labels, gate).statusSetting).toMatchObject({ tp: 0, provisionalTp: 3, labeled: 4 });
    const gap = population(120, 0, 10);
    gap.labels.pop();
    expect(scoreBenchmark(gap.findings, gap.labels, gate).gate.reasons.join(" ")).toMatch(/unlabeled/);
  });

  it("judges each repository's status by whether a true issue sets it", () => {
    const findings: BenchFinding[] = [
      { repo: "a", id: "1", severity: "CRITICAL", attackClass: "x" },
      { repo: "b", id: "2", severity: "WARNING", attackClass: "x" },
      { repo: "b", id: "3", severity: "WARNING", attackClass: "x" },
    ];
    const labels: BenchLabel[] = [{ repo: "a", id: "1", labelers: [no, no] }, { repo: "b", id: "2", labelers: [no, no] }, { repo: "b", id: "3", labelers: [yes, yes] }];
    const report = scoreBenchmark(findings, labels, gate);
    expect(report.repositories).toEqual([{ repo: "a", status: "exposed", correct: false }, { repo: "b", status: "at_risk", correct: true }]);
    expect(report.bySeverity.CRITICAL).toMatchObject({ n: 1, tp: 0, fp: 1 });
    expect(report.byClass.x).toMatchObject({ n: 3, tp: 1 });
  });
});

// A8 runs in paced batches, and re-check runs (the R1 guard fix) re-read
// repositories a batch already scored. The running total is the bench over
// the union, never a hand sum, and a finding counts once.
describe("combineBatches", () => {
  const f = (repo: string, id: string): BenchFinding => ({ repo, id, severity: "CRITICAL", attackClass: "missing_authorization" });
  it("unions batches and keeps a finding seen twice once, with the labels it was first given", () => {
    const out = combineBatches([
      { name: "b1", findings: [f("r1", "a"), f("r1", "b")], labels: [{ repo: "r1", id: "a", labelers: [yes, yes] }, { repo: "r1", id: "b", labelers: [yes, no] }] },
      { name: "b1-recheck", findings: [f("r1", "b"), f("r1", "c")], labels: [{ repo: "r1", id: "b", labelers: [yes, yes] }, { repo: "r1", id: "c", labelers: [yes, yes] }] },
    ]);
    expect(out.findings.map((x) => x.id)).toEqual(["a", "b", "c"]);
    expect(out.labels.find((l) => l.id === "b")?.labelers).toEqual([yes, no]);
    expect(out.duplicates).toEqual([{ repo: "r1", id: "b", first: "b1", again: "b1-recheck" }]);
    const report = scoreBenchmark(out.findings, out.labels, gate);
    expect(report.statusSetting).toMatchObject({ n: 3, labeled: 3, tp: 2 });
  });
});
