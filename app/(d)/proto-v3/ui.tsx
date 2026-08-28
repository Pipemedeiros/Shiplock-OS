"use client";

import { Check, Minus } from "lucide-react";
import { LockMark } from "@/components/d/Brand";
import {
  CONFIDENCE_RULE, ORIGIN_LABEL,
  type Claim, type Confidence, type Gate, type Risk, type Severity,
} from "./data";

export function Mark({ size = 20 }: { size?: number }) {
  return <LockMark size={size} />;
}

export function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="v3-eyebrow">{children}</p>;
}

export function Sev({ severity }: { severity: Severity }) {
  return <span className={`v3-sev ${severity}`}><i />{severity}</span>;
}

/** The confidence label carries its own definition — hover, and it explains itself. */
export function Conf({ confidence }: { confidence: Confidence }) {
  return <span className={`v3-conf ${confidence}`} title={CONFIDENCE_RULE[confidence]}>{confidence}</span>;
}

export function Chain({ risk, compact = false }: { risk: Risk; compact?: boolean }) {
  return (
    <div className={`v3-chain${compact ? " compact" : ""}`}>
      {risk.path.map((node, i) => (
        <div className="v3-chain-step" key={node.label}>
          {i > 0 ? <span className="v3-chain-arrow">→</span> : null}
          <div className={`v3-node ${node.kind}`} title={node.detail}>
            <b>{node.label}</b>
            <small>{node.detail}</small>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * The evidence ledger: every claim with the collector that produced it.
 * This is what makes a finding auditable rather than merely asserted.
 */
export function Claims({ claims }: { claims: Claim[] }) {
  return (
    <div className="v3-claims">
      {claims.map((c) => (
        <div className="v3-claim" key={c.claim}>
          <span className="v3-claim-check">{c.verified ? <Check size={15} /> : <Minus size={15} />}</span>
          <span>{c.claim}</span>
          <span className="v3-claim-origin">{ORIGIN_LABEL[c.origin]}</span>
        </div>
      ))}
    </div>
  );
}

export function Gates({ gates }: { gates: Gate[] }) {
  return (
    <div>
      {gates.map((g) => (
        <div className={`v3-gate${g.passed ? " passed" : ""}`} key={g.label}>
          <span>{g.passed ? <Check size={15} /> : <Minus size={15} />}</span>
          <div><b>{g.label}</b><small>{g.detail}</small></div>
        </div>
      ))}
    </div>
  );
}

/** Renders a diff with added and removed lines coloured. Plain code passes through. */
export function Code({ children }: { children: string }) {
  const lines = children.split("\n");
  const isDiff = lines.some((l) => l.startsWith("+") || l.startsWith("-"));
  if (!isDiff) return <div className="v3-code">{children}</div>;
  return (
    <div className="v3-code">
      {lines.map((line, i) => (
        <span key={`${i}-${line}`} className={line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : undefined}>
          {line || " "}
        </span>
      ))}
    </div>
  );
}
