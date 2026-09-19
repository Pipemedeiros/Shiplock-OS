/** Offline evaluation projections. Never confuse candidate recall with model recall. */
export interface EvaluationLabel {
  route: string;
  verdict: "vulnerable" | "benign";
}

export function summarizeEvaluation(
  labels: EvaluationLabel[],
  observed: Set<string>,
  prompted: Set<string>,
  replayAdmitted: Set<string>,
  reworded: Set<string>,
) {
  const positives = labels.filter((label) => label.verdict === "vulnerable");
  const negatives = labels.filter((label) => label.verdict === "benign");
  const eligiblePositive = positives.filter((label) => prompted.has(label.route)).length;
  const replayTrue = positives.filter((label) => replayAdmitted.has(label.route)).length;
  const replayFalse = negatives.filter((label) => replayAdmitted.has(label.route)).length;
  return {
    labeledRoutes: labels.length,
    vulnerableLabels: positives.length,
    benignLabels: negatives.length,
    missingLabeledRoutes: labels.filter((label) => !observed.has(label.route)).map((label) => label.route),
    promptedVulnerableLabels: eligiblePositive,
    candidateCoverage: positives.length > 0 ? eligiblePositive / positives.length : null,
    replayAdmittedTrue: replayTrue,
    replayAdmittedFalse: replayFalse,
    replayRejected: labels.length - replayTrue - replayFalse,
    rewordedLabels: labels.filter((label) => reworded.has(label.route)).length,
    // A replay of deliberately supplied proposals measures the guard, not the
    // model's ability to propose them. INFO rewording never shrinks the labels.
    modelPrecision: null,
    modelRecall: null,
  };
}
