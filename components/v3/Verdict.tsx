import Link from "next/link";
import type { ReactNode } from "react";
import type { Verdict as VerdictData } from "@/lib/verdict";

const GLYPH: Record<VerdictData["level"], string> = { exposed: "!", at_risk: "▲", nothing_open: "○", unknown: "?" };

export interface Layer { href: string; label: string; value: string; plain: string; engineer: string; tone?: "crit" | "warn" | "muted" }

/** The first thing on the Overview: are you cooked, in one word, with the
 * same facts in plain words or engineer detail, and one next step. Each layer
 * tile opens the page that proves it. */
export function Verdict({ verdict, context, action, layers }: { verdict: VerdictData; context: ReactNode; action: ReactNode; layers: Layer[] }) {
  return (
    <section className={`v3-verdict lvl-${verdict.level}`} aria-labelledby="verdict-word">
      <div className="v3-verdict-main">
        <p className="v3-verdict-ctx">{context}</p>
        <h1 id="verdict-word" className="v3-verdict-word">
          <span className="v3-verdict-glyph" aria-hidden="true">{GLYPH[verdict.level]}</span>
          {verdict.word}
        </h1>
        <p className="v3-verdict-say plain">{verdict.plain}</p>
        <p className="v3-verdict-say eng">{verdict.engineer}</p>
        <div className="v3-row" style={{ marginTop: 18 }}>{action}</div>
      </div>
      <ul className="v3-verdict-layers">
        {layers.map((l) => (
          <li key={l.label}>
            <Link href={l.href} className={`v3-vt tone-${l.tone ?? "muted"}`}>
              <span className="v3-vt-label">{l.label}</span>
              <b className="v3-vt-value">{l.value}</b>
              <span className="v3-vt-sub plain">{l.plain}</span>
              <span className="v3-vt-sub eng">{l.engineer}</span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
