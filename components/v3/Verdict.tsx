import Link from "next/link";
import type { ReactNode } from "react";
import type { Verdict as VerdictData } from "@/lib/verdict";

const GLYPH: Record<VerdictData["level"], string> = { exposed: "!", at_risk: "▲", clear: "✓", unknown: "?" };

/** The status at the top of the Overview: one word with a glyph (never colour
 * alone), one line, one next step. */
export function Verdict({ verdict, action }: { verdict: VerdictData; action: ReactNode }) {
  return (
    <section className={`v3-verdict lvl-${verdict.level}`} aria-label="Status">
      <span className="v3-verdict-glyph" aria-hidden="true">{GLYPH[verdict.level]}</span>
      <div style={{ minWidth: 0 }}>
        <p className="v3-verdict-word">{verdict.word}</p>
        <p className="v3-verdict-say">{verdict.summary}</p>
      </div>
      <div className="v3-verdict-act">{action}</div>
    </section>
  );
}

/** A Stripe-style metric: label, number, one link. */
export function Metric({ label, value, href, link, tone }: { label: string; value: number; href: string; link: string; tone?: "crit" | "warn" }) {
  return (
    <Link href={href} className={`v3-metric${tone && value > 0 ? ` tone-${tone}` : ""}`}>
      <span className="v3-metric-label">{label}</span>
      <b className="v3-metric-value">{value.toLocaleString("en-US")}</b>
      <span className="v3-metric-link">{link}</span>
    </Link>
  );
}
