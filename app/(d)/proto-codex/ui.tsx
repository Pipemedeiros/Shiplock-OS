"use client";

import {
  ArrowDownRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  Circle,
  Copy,
  ExternalLink,
  GitBranch,
  LoaderCircle,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { LockMark } from "@/components/d/Brand";
import type { Confidence, Risk, Severity } from "./data";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <span className="cx-brand">
      <span className="cx-brand-mark"><LockMark size={compact ? 18 : 22} /></span>
      <span className="cx-brand-name">ShipLock</span>
      {!compact ? <span className="cx-concept-tag">Concept 02</span> : null}
    </span>
  );
}

export function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="cx-eyebrow"><span />{children}</p>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`cx-badge is-${severity}`}><i />{severity}</span>;
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const icon = confidence === "proven" ? <ShieldCheck size={12} /> : confidence === "corroborated" ? <Sparkles size={12} /> : <Circle size={10} />;
  return <span className={`cx-confidence is-${confidence}`}>{icon}{confidence}</span>;
}

export function StatusPill({ tone, children }: { tone: "verified" | "signal" | "attention" | "quiet" | "bronze"; children: React.ReactNode }) {
  return <span className={`cx-status is-${tone}`}><i />{children}</span>;
}

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: React.ReactNode;
  description?: string;
  actions?: React.ReactNode;
}) {
  return (
    <header className="cx-page-header cx-reveal">
      <div>
        <Eyebrow>{eyebrow}</Eyebrow>
        <h1>{title}</h1>
        {description ? <p className="cx-page-description">{description}</p> : null}
      </div>
      {actions ? <div className="cx-header-actions">{actions}</div> : null}
    </header>
  );
}

export function Metric({
  label,
  value,
  detail,
  trend,
  tone = "ink",
}: {
  label: string;
  value: string;
  detail: string;
  trend?: "up" | "down";
  tone?: "ink" | "signal" | "verified" | "bronze";
}) {
  return (
    <article className={`cx-metric is-${tone} cx-reveal`}>
      <div className="cx-metric-top">
        <span>{label}</span>
        {trend === "up" ? <ArrowUpRight size={15} /> : trend === "down" ? <ArrowDownRight size={15} /> : <span className="cx-metric-rule" />}
      </div>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
  );
}

export function MiniSparkline({ tone = "bronze" }: { tone?: "bronze" | "verified" | "signal" }) {
  return (
    <svg className={`cx-sparkline is-${tone}`} viewBox="0 0 150 42" aria-hidden="true">
      <path className="cx-sparkline-grid" d="M0 35H150M0 20H150M0 5H150" />
      <path className="cx-sparkline-fill" d="M0 35 12 30 24 32 36 20 48 24 60 17 72 21 84 9 96 14 108 7 120 10 132 5 150 8V42H0Z" />
      <path className="cx-sparkline-line" d="M0 35 12 30 24 32 36 20 48 24 60 17 72 21 84 9 96 14 108 7 120 10 132 5 150 8" />
      <circle cx="132" cy="5" r="3" />
    </svg>
  );
}

export function ExposureRadar({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`cx-radar${compact ? " is-compact" : ""}`} aria-label="Animated application exposure map">
      <div className="cx-radar-grid" />
      <div className="cx-radar-sweep" />
      <div className="cx-radar-ring is-one" />
      <div className="cx-radar-ring is-two" />
      <div className="cx-radar-ring is-three" />
      <div className="cx-radar-axis is-x" />
      <div className="cx-radar-axis is-y" />
      <span className="cx-radar-label is-north">Entries · 63</span>
      <span className="cx-radar-label is-east">Assets · 24</span>
      <span className="cx-radar-label is-south">Identities · 3</span>
      <span className="cx-radar-label is-west">Paths · 4</span>
      <span className="cx-radar-node is-a"><i />invoice/:id</span>
      <span className="cx-radar-node is-b"><i />webhook</span>
      <span className="cx-radar-node is-c"><i />uploads</span>
      <span className="cx-radar-center"><LockMark size={compact ? 24 : 36} /></span>
    </div>
  );
}

export function RiskPath({ risk, compact = false }: { risk: Risk; compact?: boolean }) {
  return (
    <div className={`cx-risk-path${compact ? " is-compact" : ""}`}>
      {risk.path.map((node, index) => (
        <div className="cx-path-piece" key={`${risk.id}-${node.label}`}>
          {index > 0 ? (
            <span className="cx-path-link" aria-hidden="true">
              <span />
              <ChevronRight size={13} />
            </span>
          ) : null}
          <div className={`cx-path-node is-${node.kind}`} title={node.detail}>
            <i />
            <span>{node.label}</span>
            {!compact ? <small>{node.detail}</small> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

export function CopyButton({ text, onCopy }: { text: string; onCopy: () => void }) {
  return (
    <button className="cx-icon-button" onClick={() => { navigator.clipboard?.writeText(text); onCopy(); }} aria-label="Copy to clipboard">
      <Copy size={15} />
    </button>
  );
}

export function RunGlyph({ phase, alert }: { phase: string; alert?: boolean }) {
  if (phase === "done") return <Check size={14} />;
  if (phase === "checkout") return <GitBranch size={14} />;
  if (phase === "proof") return <ShieldCheck size={14} />;
  if (alert) return <span className="cx-trace-alert">!</span>;
  return <LoaderCircle size={14} />;
}

export function EmptyButtonLink({ children }: { children: React.ReactNode }) {
  return <span className="cx-link-affordance">{children}<ExternalLink size={13} /></span>;
}
