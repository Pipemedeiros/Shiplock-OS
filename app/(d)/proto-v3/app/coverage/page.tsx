"use client";

import { STACK_BLIND, STACK_SEEN } from "../../data";
import { useStore } from "../../store";
import { Eyebrow } from "../../ui";

export default function Coverage() {
  const { toast } = useStore();

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <Eyebrow>What we read, and what we did not</Eyebrow>
          <h1 className="v3-serif">Coverage</h1>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Read from your repository</h2>
            <span className="v3-small">Every row names how we know</span>
          </div>
          <div className="v3-card-p v3-cov">
            {STACK_SEEN.map((s) => (
              <div key={s.name}>
                <b>{s.name}</b>
                <span style={{ fontSize: 14, color: "var(--muted)" }}>{s.detail}</span>
                <small>{s.source}</small>
              </div>
            ))}
          </div>
        </div>

        {/*
          The honest half. Absent is not the same as clean, and a thinner audit
          must never look like a cleaner one.
        */}
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Not covered by this audit</h2>
            <span className="v3-small">And what would change that</span>
          </div>
          <div className="v3-card-p v3-cov">
            {STACK_BLIND.map((b) => (
              <div key={b.name}>
                <b>{b.name}</b>
                <span style={{ fontSize: 14, color: "var(--muted)" }}>
                  {b.why}
                  <small style={{ display: "block", marginTop: 5, fontFamily: "inherit", fontSize: 13 }}>{b.effect}</small>
                </span>
                {b.upgrade ? (
                  <button className="v3-btn v3-btn-sm v3-ghost" onClick={() => toast(`${b.upgrade} — optional, never required`)}>
                    {b.upgrade}
                  </button>
                ) : (
                  <span className="v3-small">Nothing to connect</span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="v3-card v3-card-p">
          <p className="v3-sub" style={{ fontSize: 14, maxWidth: 700 }}>
            Connecting a database or the edge snippet raises findings from inferred to proven. Neither
            is a setup step, and nothing is withheld until you add one — they change how certain we
            can be, not what we look for.
          </p>
        </div>
      </div>
    </>
  );
}
