import Link from "next/link";
import { Check, CircleHelp, ShieldCheck } from "lucide-react";
import type { AttackFeed, AttackStepState } from "@/lib/agent/attackFeed";

/**
 * The attack, as it happens (A3, Felipe 2026-10-07). What the customer's agent
 * tried against their code and what each attempt came to, from the real task
 * states. Every state is a glyph and words, never colour alone; the only
 * motion is the "being checked" dot, which reduced motion stops.
 */
const STATE: Record<AttackStepState, { word: string; note: string }> = {
  confirmed: { word: "Confirmed", note: "proved with quoted lines; the proof is on the issue" },
  refuted: { word: "Refuted", note: "the code blocks it" },
  could_not_tell: { word: "Could not tell", note: "it depends on code or settings the agent was not shown" },
  checking: { word: "Being checked", note: "your agent is testing it against the code" },
};

function Glyph({ state }: { state: AttackStepState }) {
  if (state === "confirmed") return <Check size={15} aria-hidden="true" style={{ color: "var(--crit)" }} />;
  if (state === "refuted") return <ShieldCheck size={15} aria-hidden="true" style={{ color: "var(--ok)" }} />;
  if (state === "checking") return <span className="v3-dot run" aria-hidden="true" />;
  return <CircleHelp size={15} aria-hidden="true" style={{ color: "var(--muted-2)" }} />;
}

export function AttackFeedCard({ feed }: { feed: AttackFeed }) {
  const intro = feed.phase === "not_offered"
    ? <>Your agent has not been asked to attack the latest audit. <Link href="/dashboard/settings">Connect your agent</Link> to run attacks.</>
    : feed.phase === "waiting_for_agent"
      ? <>Waiting for your agent to pick up the attack. ShipLock cannot start it: open Claude Code or Codex with ShipLock connected.</>
      : feed.phase === "agent_unavailable"
        ? <>Your agent did not answer this attack. Nothing it might have found is counted.</>
        : feed.proposed === 0
          ? <>Your agent read the code and proposed no attack.</>
          : <>Your agent proposed {feed.proposed} {feed.proposed === 1 ? "attack" : "attacks"}. Each one counts only when it is proved with quoted lines from your code.</>;
  return (
    <div className="v3-card">
      <div className="v3-hd">
        <h2 className="v3-eyebrow">Attack</h2>
        <span className="v3-small">On your code, never your production app</span>
      </div>
      <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <p className="v3-small" style={{ color: "var(--ink)" }}>{intro}</p>
        {feed.steps.length > 0 ? (
          <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 10 }}>
            {feed.steps.map((s) => (
              <li key={`${s.entry}-${s.title}`} style={{ display: "grid", gridTemplateColumns: "18px minmax(0, 1fr)", gap: 10, alignItems: "start" }}>
                <span style={{ paddingTop: 2 }}><Glyph state={s.state} /></span>
                <span style={{ minWidth: 0 }}>
                  <span style={{ display: "block", overflowWrap: "anywhere" }}>{s.title}</span>
                  <span className="v3-small" style={{ overflowWrap: "anywhere" }}>
                    <span className="v3-mono">{s.entry}</span> · <b style={{ fontWeight: 500 }}>{STATE[s.state].word}</b>, {STATE[s.state].note}
                    {s.state === "confirmed" ? <> · <Link href="/dashboard/risks">See the issue</Link></> : null}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </div>
  );
}
