"use client";

import type { Confidence, Severity } from "./data";

export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden>
      <path d="M8 10V7.5a4 4 0 0 1 8 0V10" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M12 2.6 20 7v10l-8 4.4L4 17V7z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
      <circle cx="12" cy="13" r="1.7" fill="currentColor" />
    </svg>
  );
}

const SEV_LABEL: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low",
};

export function SevTag({ s }: { s: Severity }) {
  const cls = s === "critical" ? "pr-tag-crit" : s === "high" ? "pr-tag-warn" : "pr-tag-mute";
  return <span className={`pr-tag ${cls}`}>{SEV_LABEL[s]}</span>;
}

const CONF: Record<Confidence, { label: string; title: string }> = {
  proven: { label: "Proven", title: "Reproduced on a disposable copy of your schema. Your data was never read." },
  corroborated: { label: "Corroborated", title: "Two independent readings of your code agree. Not replayed." },
  inferred: { label: "Inferred", title: "Read from the code alone. Something outside the repo could compensate." },
};

export function ConfTag({ c }: { c: Confidence }) {
  const cls = c === "proven" ? "pr-tag-ok" : "pr-tag-mute";
  return <span className={`pr-tag ${cls}`} title={CONF[c].title}>{CONF[c].label}</span>;
}
