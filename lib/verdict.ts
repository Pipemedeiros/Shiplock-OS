import type { Severity } from "@/lib/types";
import type { Confidence } from "@/lib/agent/findings";

/** The status at the top of the Overview, from the audit's own facts. It
 * names what was found and what was not checked; it never says secure. */
export type VerdictLevel = "exposed" | "at_risk" | "clear" | "unknown";

export interface VerdictInput {
  audited: boolean;
  lastRunFailed: boolean;
  findings: { severity: Severity; confidence: Confidence }[];
  /** Coverage notes on the last audit: areas it did not read. */
  unread: number;
  /** Recent pull requests ShipLock's check blocked. */
  blockedPrs: number;
}

export interface Verdict { level: VerdictLevel; word: string; summary: string }

const n = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;

export function verdictOf(input: VerdictInput): Verdict {
  const criticals = input.findings.filter((f) => f.severity === "CRITICAL").length;
  const warnings = input.findings.filter((f) => f.severity === "WARNING").length;

  if (criticals > 0) {
    return { level: "exposed", word: "Exposed", summary: `${n(criticals, "critical issue exposes", "critical issues expose")} customer data.` };
  }
  if (warnings > 0 || input.blockedPrs > 0) {
    return { level: "at_risk", word: "At risk",
      summary: warnings > 0 ? `${n(warnings, "warning needs", "warnings need")} review.` : `${n(input.blockedPrs, "pull request was", "pull requests were")} blocked.` };
  }
  if (!input.audited) return { level: "unknown", word: "Not audited", summary: "Run an audit to see your status." };
  if (input.lastRunFailed) return { level: "unknown", word: "Unknown", summary: "The last audit did not finish." };
  return { level: "clear", word: "No open issues",
    summary: input.unread > 0 ? `${n(input.unread, "area was", "areas were")} not checked.` : "In the code this audit read." };
}

/** The audit in progress, if the newest run is queued or running, and the
 * newest finished run the status should read meanwhile. */
export function auditState<R extends { status: string }>(runs: readonly R[]): { current: R | null; finished: R | null } {
  const current = runs[0] && (runs[0].status === "queued" || runs[0].status === "running") ? runs[0] : null;
  return { current, finished: runs.find((r) => r.status === "complete" || r.status === "failed") ?? null };
}
