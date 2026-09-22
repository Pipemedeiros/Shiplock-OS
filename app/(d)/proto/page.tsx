"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { PATHS, PROTO_PLANS, UNIT } from "./data";
import { useProto } from "./store";
import { ConfTag, Mark, SevTag } from "./ui";

export default function ProtoLanding() {
  const { set, toast, billing } = useProto();
  const [internals, setInternals] = useState(false);

  return (
    <>
      {/* ── hero ── */}
      <div className="pr-band">
        <div className="pr-shell">
          <nav className="pr-nav">
            <Link href="/proto" className="pr-mark"><Mark /> ShipLock</Link>
            <div className="pr-nav-links">
              <a href="#how">How it works</a>
              <a href="#pricing">Pricing</a>
              <Link href="/proto/app">Live demo</Link>
              <Link href="/proto/onboarding" className="pr-btn pr-btn-onnavy pr-btn-sm">Connect GitHub</Link>
            </div>
          </nav>

          <div style={{ padding: "72px 0 80px", maxWidth: 760 }}>
            <p className="pr-eyebrow pr-eyebrow-navy">Application security · one connection</p>
            <h1 className="pr-serif" style={{ fontSize: 50, lineHeight: 1.1, margin: "18px 0 20px" }}>
              A security engineer that reads your repository and everything it touches.
            </h1>
            <p style={{ fontSize: 18, color: "var(--muted-navy)", maxWidth: 620 }}>
              Connect GitHub. Nothing else. Your code already names your auth provider, your
              database, your payment webhooks and your buckets — so we read those from the
              source instead of asking you to wire up five dashboards.
            </p>
            <div className="pr-row" style={{ marginTop: 30 }}>
              <Link href="/proto/onboarding" className="pr-btn pr-btn-primary">Run a free first audit</Link>
              <Link href="/proto/app" className="pr-btn pr-btn-onnavy">See a finished audit</Link>
            </div>
            <p className="pr-mono" style={{ marginTop: 18, fontSize: 12, color: "var(--muted-navy)" }}>
              Read-only access · your database is never read · findings in ~4 minutes
            </p>
          </div>
        </div>
      </div>

      {/* ── the argument ── */}
      <div className="pr-shell" style={{ padding: "64px 0" }} id="how">
        <div className="pr-grid-3">
          {[
            {
              n: "01", h: "It reads the code the way an attacker would",
              b: "Not a linter pass. It walks in from every route handler, follows the guard, and asks what data it can reach. Findings are paths, not line numbers.",
            },
            {
              n: "02", h: "It reasons about the rest of your stack from the code",
              b: "Clerk resolves a user here but not an organisation. This Stripe webhook writes billing state without verifying a signature. Your database URL is reachable from a client component. None of that needed a second integration.",
            },
            {
              n: "03", h: "It proves what it can, and says so when it can't",
              b: "Where a finding can be reproduced, we rebuild your schema — never your data — on a disposable copy and reproduce it there. Everything else is labelled inferred.",
            },
          ].map((c) => (
            <div key={c.n} className="pr-card pr-card-p">
              <p className="pr-eyebrow">{c.n}</p>
              <h3 style={{ fontSize: 17, margin: "10px 0 8px" }}>{c.h}</h3>
              <p className="pr-sub">{c.b}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── sample finding ── */}
      <div style={{ background: "var(--paper)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div className="pr-shell" style={{ padding: "60px 0" }}>
          <p className="pr-eyebrow">What a finding looks like</p>
          <h2 className="pr-serif" style={{ fontSize: 30, margin: "12px 0 26px", maxWidth: 620 }}>
            The blast radius first. The file and line underneath it.
          </h2>
          <SampleFinding />
        </div>
      </div>

      {/* ── pricing ── */}
      <div className="pr-shell" style={{ padding: "70px 0" }} id="pricing">
        <div className="pr-between" style={{ alignItems: "flex-end", marginBottom: 26 }}>
          <div>
            <p className="pr-eyebrow">Pricing</p>
            <h2 className="pr-serif" style={{ fontSize: 32, margin: "10px 0 6px" }}>
              Priced per codebase, not per seat.
            </h2>
            <p className="pr-sub" style={{ maxWidth: 560 }}>
              Inviting your whole team costs nothing. What costs us money is the size of the
              code we read and how often you ship, so that is what we charge for.
            </p>
          </div>
          <div className="pr-toggle">
            <button className={billing === "monthly" ? "on" : ""} onClick={() => set({ billing: "monthly" })}>Monthly</button>
            <button className={billing === "annual" ? "on" : ""} onClick={() => set({ billing: "annual" })}>Annual · save 20%</button>
          </div>
        </div>

        <div className="pr-plans">
          {PROTO_PLANS.map((p) => {
            const price = billing === "annual" ? p.annualMonthly : p.monthly;
            const gm = Math.round(((price - p.cogs) / price) * 100);
            return (
              <div key={p.id} className={`pr-plan${p.featured ? " featured" : ""}`}>
                <div>
                  <div className="pr-between">
                    <h3 style={{ fontSize: 16 }}>{p.name}</h3>
                    {p.featured ? <span className="pr-tag pr-tag-ok">Most teams</span> : null}
                  </div>
                  <p className="pr-sub" style={{ fontSize: 13, marginTop: 6 }}>{p.who}</p>
                </div>
                <div>
                  <span className="pr-plan-price">${price.toLocaleString()}</span>
                  <span className="pr-sub" style={{ marginLeft: 6 }}>
                    {p.id === "enterprise" ? "/mo, from" : "/mo"}
                  </span>
                  {billing === "annual" && p.id !== "enterprise" ? (
                    <p className="pr-sub" style={{ fontSize: 12.5, marginTop: 4 }}>
                      billed annually · ${p.monthly}/mo month-to-month
                    </p>
                  ) : null}
                </div>
                <ul>
                  {p.limits.map((l) => <li key={l}>{l}</li>)}
                </ul>
                <hr className="pr-rule" />
                <ul>
                  {p.features.map((f) => <li key={f}>{f}</li>)}
                </ul>
                {internals ? (
                  <div className="pr-mono" style={{ fontSize: 11.5, color: "var(--muted)", borderTop: "1px dashed var(--line)", paddingTop: 10 }}>
                    COGS ${p.cogs}/mo · gross margin {gm}%
                    {gm < 75 ? <span style={{ color: "var(--crit)" }}> · below floor</span> : null}
                  </div>
                ) : null}
                <Link
                  href={p.id === "enterprise" ? "/proto/app/settings" : "/proto/onboarding"}
                  className={`pr-btn ${p.featured ? "pr-btn-primary" : "pr-btn-ghost"}`}
                  onClick={() => set({ plan: p.id })}
                >
                  {p.cta}
                </Link>
              </div>
            );
          })}
        </div>

        <div className="pr-between" style={{ marginTop: 18 }}>
          <p className="pr-sub" style={{ fontSize: 13 }}>
            Over a limit we email you before we charge you. Extra repository $39/mo · extra 100
            Pricing is under measurement and will be set from real usage costs.
          </p>
          <button className="pr-btn pr-btn-ghost pr-btn-sm" onClick={() => { setInternals(!internals); toast(internals ? "Unit economics hidden" : "Internal view — COGS and margin per plan"); }}>
            {internals ? "Hide" : "Show"} unit economics
          </button>
        </div>

        <div style={{ marginTop: 30 }}>
          <Sizer />
        </div>
      </div>

      <div className="pr-band">
        <div className="pr-shell" style={{ padding: "26px 0", fontSize: 13, color: "var(--muted-navy)" }}>
          <div className="pr-between">
            <span>Prototype · demo data only · nothing here calls a real service</span>
            <Link href="/proto/app" style={{ textDecoration: "none" }}>Open the product →</Link>
          </div>
        </div>
      </div>
    </>
  );
}

function SampleFinding() {
  const p = PATHS[0];
  return (
    <div className="pr-card">
      <div className="pr-hd">
        <div className="pr-row">
          <SevTag s={p.severity} />
          <ConfTag c={p.confidence} />
        </div>
        <span className="pr-file">{p.evidenceFile}</span>
      </div>
      <div className="pr-card-p">
        <h3 className="pr-serif" style={{ fontSize: 22 }}>{p.title}</h3>
        <p className="pr-sub" style={{ marginTop: 8, maxWidth: 620 }}>{p.consequence}</p>
        <div className="pr-chain">
          {p.chain.map((n, i) => (
            <span key={n.label} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
              {i > 0 ? <span className="pr-arrow">→</span> : null}
              <span className={`node${n.broken ? " bad" : ""}`}>{n.label}</span>
            </span>
          ))}
        </div>
        <div className="pr-code" style={{ marginTop: 18 }}>{p.evidence}</div>
      </div>
    </div>
  );
}

/** Sizing calculator — picks the plan from the shape of the customer's codebase. */
function Sizer() {
  const [lines, setLines] = useState(140);      // thousands
  const [prs, setPrs] = useState(80);           // per month
  const [repos, setRepos] = useState(3);
  const { billing } = useProto();

  const { plan, cogs, price, gm } = useMemo(() => {
    // Deep re-audits run every 48 hours on the Startup cadence — 15 a month.
    const deep = lines * 1000 * UNIT.deepAuditPerLine * 15;
    const pr = prs * UNIT.prAudit;
    const proof = Math.min(prs, 40) * UNIT.proofRun;
    const platform = repos * UNIT.platformPerRepo;
    const total = deep + pr + proof + platform + UNIT.supportPerSeat * 5;

    const pick =
      repos <= 1 && lines <= 50 && prs <= 30 ? PROTO_PLANS[0]
      : repos <= 5 && lines <= 250 && prs <= 200 ? PROTO_PLANS[1]
      : repos <= 20 && lines <= 1500 && prs <= 750 ? PROTO_PLANS[2]
      : PROTO_PLANS[3];

    const p = billing === "annual" ? pick.annualMonthly : pick.monthly;
    return { plan: pick, cogs: total, price: p, gm: Math.round(((p - total) / p) * 100) };
  }, [lines, prs, repos, billing]);

  return (
    <div className="pr-card">
      <div className="pr-hd">
        <h3 className="pr-eyebrow">Which plan fits</h3>
        <span className="pr-sub" style={{ fontSize: 13 }}>Move the sliders to your codebase.</span>
      </div>
      <div className="pr-card-p pr-grid-2" style={{ alignItems: "center" }}>
        <div className="pr-stack">
          <div className="pr-field">
            <label>Lines of code <span className="pr-mono">{lines}k</span></label>
            <input type="range" min={10} max={2000} step={10} value={lines} onChange={(e) => setLines(+e.target.value)} />
          </div>
          <div className="pr-field">
            <label>Pull requests per month <span className="pr-mono">{prs}</span></label>
            <input type="range" min={5} max={900} step={5} value={prs} onChange={(e) => setPrs(+e.target.value)} />
          </div>
          <div className="pr-field">
            <label>Repositories <span className="pr-mono">{repos}</span></label>
            <input type="range" min={1} max={30} value={repos} onChange={(e) => setRepos(+e.target.value)} />
          </div>
        </div>
        <div style={{ borderLeft: "1px solid var(--line)", paddingLeft: 24 }}>
          <p className="pr-eyebrow">Recommended</p>
          <p className="pr-serif" style={{ fontSize: 30, margin: "6px 0" }}>{plan.name}</p>
          <p className="pr-sub">{plan.who}</p>
          <p style={{ marginTop: 14, fontSize: 22 }} className="pr-serif">
            ${price.toLocaleString()}<span className="pr-sub" style={{ fontSize: 14 }}>/mo</span>
          </p>
          <p className="pr-mono" style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 12 }}>
            internal · cost to serve ≈ ${cogs.toFixed(0)}/mo · margin {gm}%
          </p>
        </div>
      </div>
    </div>
  );
}
