import Link from "next/link";
import { AlertTriangle, CheckCircle2, Circle, Clock, Loader2 } from "lucide-react";
import type { LoopStage, LoopState } from "@/lib/securityLoop";

/** Each state as a word and a glyph, never colour alone. */
const STATE: Record<LoopState, { word: string; tone: string; Icon: typeof Circle }> = {
  done: { word: "Done", tone: "ok", Icon: CheckCircle2 },
  working: { word: "In progress", tone: "", Icon: Loader2 },
  waiting: { word: "Waiting", tone: "warn", Icon: Clock },
  attention: { word: "Needs you", tone: "crit", Icon: AlertTriangle },
  off: { word: "Not run", tone: "", Icon: Circle },
};

/**
 * Read, attack, map, fix, watch (Felipe 2026-10-06), in that order, each
 * with what actually happened and a link to its evidence. Numbered and
 * joined by a hairline, solid after a finished stage, so it reads as one run.
 */
export function SecurityLoop({ stages }: { stages: LoopStage[] }) {
  return (
    <ol className="v3-loop" aria-label="Security loop">
      {stages.map((s, i) => {
        const { word, tone, Icon } = STATE[s.state];
        return (
          <li key={s.key} className={s.state === "done" ? "done" : ""}>
            <Link href={s.href} className={`v3-metric v3-loop-stage${s.state === "off" ? " off" : ""}`}>
              <span className="v3-between">
                <span className="v3-metric-label"><span className="v3-loop-n" aria-hidden="true">{i + 1}</span>{s.title}</span>
                <span className={`v3-tag ${tone}`}>
                  <Icon size={12} aria-hidden="true" className={s.state === "working" ? "v3-spin" : undefined} />{word}
                </span>
              </span>
              <b className="v3-loop-head">{s.headline}</b>
              <span className="v3-small">{s.detail}</span>
              {s.action ? <span className="v3-metric-link">{s.action}</span> : null}
            </Link>
          </li>
        );
      })}
    </ol>
  );
}
