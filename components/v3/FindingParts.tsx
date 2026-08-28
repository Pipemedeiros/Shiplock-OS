import { Check, Minus } from "lucide-react";
import type { Severity } from "@/lib/types";
import type { Claim, Confidence } from "@/lib/agent/findings";

/**
 * The small pieces every finding surface reuses.
 *
 * Severity is a word and a dot, never a filled panel: a dashboard that turns
 * red is a dashboard people stop opening. The only red surface in the whole
 * design is the node in a path that actually failed.
 */

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "critical",
  WARNING: "warning",
  INFO: "info",
};

const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL: "critical",
  WARNING: "high",
  INFO: "medium",
};

export function Sev({ severity }: { severity: Severity }) {
  return (
    <span className={`v3-sev ${SEVERITY_CLASS[severity] ?? "medium"}`}>
      <i />
      {SEVERITY_LABEL[severity] ?? "finding"}
    </span>
  );
}

/** Each confidence label carries its own definition, so it never has to be trusted blind. */
const CONFIDENCE_RULE: Record<Confidence, string> = {
  proven: "Reproduced on a disposable copy of your schema. None of your data was read.",
  corroborated: "Two or more independent readings of your code agree. We did not run it.",
  inferred: "One reading of your code. Something outside the repository could compensate for it.",
};

export function Conf({ confidence }: { confidence: Confidence }) {
  return (
    <span className={`v3-conf ${confidence}`} title={CONFIDENCE_RULE[confidence]}>
      {confidence}
    </span>
  );
}

/** The path, drawn from what the collectors recorded rather than from prose. */
export function Chain({
  entry,
  file,
  blastRadius,
}: {
  entry: string;
  file: string | null;
  blastRadius: string | null;
}) {
  return (
    <>
      <div className="v3-chain">
        <div className="v3-chain-step">
          <div className="v3-node entry">
            <b>{entry}</b>
            <small>entry point</small>
          </div>
        </div>
        <div className="v3-chain-step">
          <span className="v3-chain-arrow">→</span>
          <div className="v3-node gap">
            <b>the check that is missing</b>
            <small>{file ?? "see the evidence"}</small>
          </div>
        </div>
        {blastRadius ? (
          <div className="v3-chain-step">
            <span className="v3-chain-arrow">→</span>
            <div className="v3-node asset">
              <b>{blastRadius}</b>
              <small>what it reaches</small>
            </div>
          </div>
        ) : null}
      </div>
    </>
  );
}

/** The evidence ledger: what we claim, where each claim came from, and whether it held. */
export function Claims({ claims }: { claims: Claim[] }) {
  if (claims.length === 0) {
    return <p className="v3-small">No reasoning was recorded for this finding.</p>;
  }

  const ORIGIN: Record<string, string> = {
    routes: "Route inventory",
    imports: "Import graph",
    schema: "Schema",
    stack: "Stack",
    secrets: "Secret scan",
    agent: "Proposed",
  };

  return (
    <div className="v3-claims">
      {claims.map((c, i) => (
        <div className="v3-claim" key={`${i}-${c.claim.slice(0, 24)}`}>
          <span className="v3-claim-check" style={{ color: c.verified ? "var(--ok)" : "var(--muted-2)" }}>
            {c.verified ? <Check size={15} /> : <Minus size={15} />}
          </span>
          <span>{c.claim}</span>
          <span className="v3-claim-origin">{ORIGIN[c.origin] ?? c.origin}</span>
        </div>
      ))}
    </div>
  );
}
