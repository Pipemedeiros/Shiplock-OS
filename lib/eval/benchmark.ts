/**
 * The harness benchmark's arithmetic (plan item H; Felipe 2026-10-06: "we can
 * only launch when 90%+ precision"). Findings as a founder sees them, labels
 * from two blind labelers, and the recorded gate in; counts, bounds, status
 * correctness and a verdict out. It never decides a threshold: the gate comes
 * from docs/evaluation/thresholds-release-2026-10-14.json (95% observed, Claude under Felipe's grant 2026-10-14), recorded before any
 * release benchmark. Pure: no I/O.
 */
export type Severity = "CRITICAL" | "WARNING" | "INFO";
export type BenchFinding = { repo: string; id: string; severity: Severity; attackClass: string };
export type Verdict = { accurate: "yes" | "partly" | "no"; real: "yes" | "no" | "unsure" };
export type BenchLabel = { repo: string; id: string; labelers: Verdict[] };
export type Gate = {
  observedPrecisionAtLeast: number; lowerBound95AtLeast: number; minimumLabeledFindings: number;
  repositoriesWithCorrectStatusAtLeast: number;
};
/** provisionalTp: every available labeler said yes, even if only one did. Reported, never gated. */
export type Tally = { n: number; labeled: number; unlabeled: number; tp: number; fp: number; provisionalTp: number; precision: number | null; lower95: number | null };
export type RepoStatus = { repo: string; status: "exposed" | "at_risk" | "no_open_issues"; correct: boolean | null };
export type BenchReport = {
  statusSetting: Tally; bySeverity: Record<Severity, Tally>; byClass: Record<string, Tally>;
  repositories: RepoStatus[]; statusCorrect: { judged: number; correct: number; share: number | null };
  gate: { result: "pass" | "fail" | "not_measurable"; reasons: string[] };
};

function logBinom(n: number, k: number): number {
  let s = 0;
  for (let i = 1; i <= k; i++) s += Math.log(n - k + i) - Math.log(i);
  return s;
}
/** P(X >= k) for X ~ Binomial(n, p). */
function upperTail(k: number, n: number, p: number): number {
  if (p <= 0) return k === 0 ? 1 : 0;
  if (p >= 1) return 1;
  let sum = 0;
  for (let i = k; i <= n; i++) sum += Math.exp(logBinom(n, i) + i * Math.log(p) + (n - i) * Math.log(1 - p));
  return sum;
}
/** Exact one-sided Clopper-Pearson lower bound on a proportion k/n. */
export function clopperPearsonLower(k: number, n: number, alpha = 0.05): number {
  if (n <= 0 || k <= 0) return 0;
  let lo = 0, hi = 1;
  for (let i = 0; i < 60; i++) {
    const mid = (lo + hi) / 2;
    if (upperTail(k, n, mid) > alpha) hi = mid; else lo = mid;
  }
  return lo;
}

/** True when two labelers both say accurate and real; when they split, a
 * third blind labeler decides by majority (tie-break, Felipe 2026-10-13,
 * recorded before release attempt 4). */
const strictYes = (v: BenchLabel["labelers"][number]) => v.accurate === "yes" && v.real === "yes";
const isTrue = (l: BenchLabel) => {
  const yes = l.labelers.filter(strictYes).length;
  return l.labelers.length === 2 ? yes === 2 : l.labelers.length >= 3 && yes * 2 > l.labelers.length;
};

function tally(findings: BenchFinding[], labels: Map<string, BenchLabel>): Tally {
  let labeled = 0, tp = 0, provisionalTp = 0;
  for (const f of findings) {
    const l = labels.get(`${f.repo}\u0000${f.id}`);
    if (!l || l.labelers.length === 0) continue;
    labeled++;
    if (isTrue(l)) tp++;
    if (l.labelers.every((v) => v.accurate === "yes" && v.real === "yes")) provisionalTp++;
  }
  const fp = labeled - tp;
  return { n: findings.length, labeled, unlabeled: findings.length - labeled, tp, fp, provisionalTp,
    precision: labeled ? tp / labeled : null, lower95: labeled ? clopperPearsonLower(tp, labeled) : null };
}

export function scoreBenchmark(findings: BenchFinding[], labels: BenchLabel[], gate: Gate): BenchReport {
  const byKey = new Map(labels.map((l) => [`${l.repo}\u0000${l.id}`, l]));
  const setting = findings.filter((f) => f.severity !== "INFO");
  const bySeverity = Object.fromEntries((["CRITICAL", "WARNING", "INFO"] as const).map((s) => [s, tally(findings.filter((f) => f.severity === s), byKey)])) as Record<Severity, Tally>;
  const byClass = Object.fromEntries([...new Set(findings.map((f) => f.attackClass))].sort().map((c) => [c, tally(findings.filter((f) => f.attackClass === c), byKey)]));

  const repositories: RepoStatus[] = [...new Set(findings.map((f) => f.repo))].sort().map((repo) => {
    const own = findings.filter((f) => f.repo === repo);
    const status = own.some((f) => f.severity === "CRITICAL") ? "exposed" : own.some((f) => f.severity === "WARNING") ? "at_risk" : "no_open_issues";
    if (status === "no_open_issues") return { repo, status, correct: null };
    // Right when a true issue of the severity that sets it exists.
    const setters = own.filter((f) => (status === "exposed" ? f.severity === "CRITICAL" : f.severity === "WARNING"));
    const judged = setters.map((f) => byKey.get(`${f.repo}\u0000${f.id}`)).filter((l): l is BenchLabel => Boolean(l && l.labelers.length));
    return { repo, status, correct: judged.length === 0 ? null : judged.some(isTrue) };
  });
  const judged = repositories.filter((r) => r.correct !== null);
  const statusCorrect = { judged: judged.length, correct: judged.filter((r) => r.correct).length,
    share: judged.length ? judged.filter((r) => r.correct).length / judged.length : null };

  const statusSetting = tally(setting, byKey);
  const reasons: string[] = [];
  let measurable = true;
  if (statusSetting.unlabeled > 0) { measurable = false; reasons.push(`${statusSetting.unlabeled} status-setting findings are unlabeled`); }
  const single = setting.filter((f) => (byKey.get(`${f.repo}\u0000${f.id}`)?.labelers.length ?? 0) === 1).length;
  if (single > 0) { measurable = false; reasons.push(`${single} findings have one label; the gate needs two labelers`); }
  if (statusSetting.labeled < gate.minimumLabeledFindings) {
    measurable = false; reasons.push(`${statusSetting.labeled} labeled findings, fewer than the ${gate.minimumLabeledFindings} the gate needs`);
  }
  let pass = measurable;
  if (measurable) {
    if ((statusSetting.precision ?? 0) < gate.observedPrecisionAtLeast) {
      pass = false; reasons.push(`precision ${(statusSetting.precision! * 100).toFixed(1)}% is below ${gate.observedPrecisionAtLeast * 100}%`);
    }
    if ((statusSetting.lower95 ?? 0) < gate.lowerBound95AtLeast) {
      pass = false; reasons.push(`lower bound ${(statusSetting.lower95! * 100).toFixed(1)}% is below ${gate.lowerBound95AtLeast * 100}%`);
    }
    if (statusCorrect.share === null || statusCorrect.share < gate.repositoriesWithCorrectStatusAtLeast) {
      pass = false; reasons.push(`status right on ${statusCorrect.correct} of ${statusCorrect.judged} repositories, below ${gate.repositoriesWithCorrectStatusAtLeast * 100}%`);
    }
  }
  return { statusSetting, bySeverity, byClass, repositories, statusCorrect,
    gate: { result: !measurable ? "not_measurable" : pass ? "pass" : "fail", reasons } };
}

export type BenchBatch = { name: string; findings: BenchFinding[]; labels: BenchLabel[] };

/**
 * The union of paced batches, for one bench over the running total (A8). A
 * re-check run re-reads repositories a batch already scored, so a finding
 * (repo and id) counts once, with the labels it was first given: a later
 * relabel never replaces an earlier verdict. Duplicates are returned so the
 * report can say what was folded.
 */
export function combineBatches(batches: BenchBatch[]) {
  const seen = new Map<string, string>();
  const findings: BenchFinding[] = [];
  const labels: BenchLabel[] = [];
  const duplicates: { repo: string; id: string; first: string; again: string }[] = [];
  for (const batch of batches) {
    const own = new Map(batch.labels.map((l) => [`${l.repo}\u0000${l.id}`, l]));
    for (const f of batch.findings) {
      const key = `${f.repo}\u0000${f.id}`;
      const first = seen.get(key);
      if (first !== undefined) { duplicates.push({ repo: f.repo, id: f.id, first, again: batch.name }); continue; }
      seen.set(key, batch.name);
      findings.push(f);
      const label = own.get(key);
      if (label) labels.push(label);
    }
  }
  return { findings, labels, duplicates };
}
