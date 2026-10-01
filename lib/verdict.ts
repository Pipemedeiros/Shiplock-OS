import type { Severity } from "@/lib/types";
import type { Confidence } from "@/lib/agent/findings";

/** One answer to "am I cooked?", from the audit's own facts. It names what
 * was found and what was not read; it never calls an app secure. */
export type VerdictLevel = "exposed" | "at_risk" | "nothing_open" | "unknown";

export interface VerdictInput {
  audited: boolean;
  lastRunFailed: boolean;
  findings: { severity: Severity; confidence: Confidence }[];
  /** Coverage notes on the last audit: areas it did not read. */
  unread: number;
  /** Recent pull requests ShipLock's check blocked. */
  blockedPrs: number;
}

export interface Verdict { level: VerdictLevel; word: string; plain: string; engineer: string }

const n = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;

export function verdictOf(input: VerdictInput): Verdict {
  const criticals = input.findings.filter((f) => f.severity === "CRITICAL");
  const warnings = input.findings.filter((f) => f.severity === "WARNING");
  const proven = input.findings.filter((f) => f.confidence === "proven").length;
  const unread = input.unread > 0 ? ` ${n(input.unread, "area was", "areas were")} not read.` : "";

  if (criticals.length > 0) {
    return {
      level: "exposed", word: "Exposed",
      plain: criticals.length === 1
        ? "Someone who should not can reach customer data today. Fix this one first."
        : `${criticals.length} ways in reach customer data today. Fix the first one now.`,
      engineer: `${n(criticals.length, "critical", "criticals")}, ${n(warnings.length, "warning", "warnings")}, ${proven} proven, from the last audit.${unread}`,
    };
  }
  if (warnings.length > 0 || input.blockedPrs > 0) {
    const parts = [warnings.length ? n(warnings.length, "warning", "warnings") : "", input.blockedPrs ? n(input.blockedPrs, "blocked pull request", "blocked pull requests") : ""].filter(Boolean);
    return {
      level: "at_risk", word: "At risk",
      plain: "Nothing reaches customer data openly, but some checks are weaker than they should be. Worth an afternoon.",
      engineer: `${parts.join(", ")}, ${proven} proven.${unread}`,
    };
  }
  if (!input.audited || input.lastRunFailed) {
    return {
      level: "unknown", word: input.audited ? "Unknown" : "Not audited yet",
      plain: input.audited ? "The last audit stopped before it finished. Run it again to get an answer." : "Run the first audit. It takes a few minutes and reads only your code.",
      engineer: input.audited ? "Last run did not complete; earlier findings stay open until a full run replaces them." : "No audit run recorded.",
    };
  }
  return {
    level: "nothing_open", word: "Nothing open",
    plain: `Nothing we read reaches customer data.${unread || " That covers what this audit read, not everything that could go wrong."}`,
    engineer: `0 critical, 0 warning open on the last audit.${unread}`,
  };
}
