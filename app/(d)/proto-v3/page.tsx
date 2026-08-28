"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ArrowRight, Check } from "lucide-react";
import { INCLUDED, PLANS, RISKS } from "./data";
import { useStore } from "./store";
import { Chain, Code, Conf, Eyebrow, Mark, Sev } from "./ui";

export default function Landing() {
  const { billing, set } = useStore();
  const sample = RISKS[0];

  return (
    <>
      {/* ── hero ─────────────────────────────────────────────────────────── */}
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <Link href="/proto-v3" className="v3-mark"><Mark /> ShipLock</Link>
            <div className="v3-nav-links">
              <a href="#how">How it works</a>
              <a href="#pricing">Pricing</a>
              <Link href="/proto-v3/app">See a finished audit</Link>
              <Link href="/proto-v3/onboarding" className="v3-btn v3-btn-sm v3-ondark">Connect GitHub</Link>
            </div>
          </nav>

          <div className="v3-grid-2" style={{ gap: 40, alignItems: "center" }}>
            <div className="v3-hero">
              <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>Application security · one connection</p>
              <h1 className="v3-serif">A security engineer that reads your repository and everything it touches.</h1>
              <p>
                Connect GitHub. Nothing else. Your code already names your auth provider, your
                database, your payment webhooks and your buckets — so we read those from the
                source instead of asking you to wire up five dashboards.
              </p>
              <div className="v3-row" style={{ marginTop: 28 }}>
                <Link href="/proto-v3/onboarding" className="v3-btn v3-primary">Run a free first audit</Link>
                <Link href="/proto-v3/app" className="v3-btn v3-ondark">See a finished audit</Link>
              </div>
              <p className="v3-mono" style={{ marginTop: 18, fontSize: 12, color: "var(--muted-navy)" }}>
                Read-only · your database is never read · TypeScript and Next.js today
              </p>
            </div>
            <RepositoryMap />
          </div>
        </div>
      </div>

      {/* ── the argument ─────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="how">
        <div className="v3-section-hd">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="v3-serif">Three things, in order.</h2>
        </div>
        <div className="v3-argument">
          {[
            {
              n: "01",
              h: "It walks in from every entry",
              b: "Not a linter pass. It starts at each route handler, follows the guard, and asks what data that route can reach. A finding is a path, not a line number.",
            },
            {
              n: "02",
              h: "It reads the rest of your stack from the code",
              b: "Your auth resolves a user here but never a workspace. This webhook writes billing state without verifying who sent it. A database helper is reachable from a client component. None of that needed a second integration.",
            },
            {
              n: "03",
              h: "It proves what it can, and says so when it can't",
              b: "Where a finding can be reproduced, we rebuild your schema — never your data — on a disposable copy and reproduce it there. Everything else is labelled, and we tell you what would make it certain.",
            },
          ].map((c) => (
            <div key={c.n}>
              <Eyebrow>{c.n}</Eyebrow>
              <h3>{c.h}</h3>
              <p className="v3-sub" style={{ fontSize: 14 }}>{c.b}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── one real finding ─────────────────────────────────────────────── */}
      <div style={{ background: "var(--paper)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div className="v3-shell v3-section">
          <div className="v3-section-hd">
            <Eyebrow>What a finding looks like</Eyebrow>
            <h2 className="v3-serif">The consequence first. The file underneath it.</h2>
          </div>
          <div className="v3-card">
            <div className="v3-hd">
              <div className="v3-row"><Sev severity={sample.severity} /><Conf confidence={sample.confidence} /></div>
              <span className="v3-file">{sample.file}</span>
            </div>
            <div className="v3-card-p">
              <h3 className="v3-serif" style={{ fontSize: 22 }}>{sample.title}</h3>
              <p className="v3-sub" style={{ marginTop: 8, maxWidth: 640 }}>{sample.consequence}</p>
              <Chain risk={sample} />
              <div style={{ marginTop: 18 }}><Code>{sample.vulnerableCode}</Code></div>
            </div>
          </div>
        </div>
      </div>

      {/* ── pricing ──────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="pricing">
        <div className="v3-between" style={{ alignItems: "flex-end", marginBottom: 26 }}>
          <div className="v3-section-hd" style={{ marginBottom: 0 }}>
            <Eyebrow>Pricing</Eyebrow>
            <h2 className="v3-serif">Priced per codebase, not per seat.</h2>
            <p className="v3-sub" style={{ fontSize: 14.5 }}>
              Inviting your whole team costs nothing. What costs us money is how much code we read
              and how often you ship, so that is what we charge for.
            </p>
          </div>
          <div className="v3-toggle">
            <button className={billing === "monthly" ? "on" : ""} onClick={() => set({ billing: "monthly" })}>Monthly</button>
            <button className={billing === "annual" ? "on" : ""} onClick={() => set({ billing: "annual" })}>Annual · save 20%</button>
          </div>
        </div>

        <div className="v3-plans">
          {PLANS.map((p) => {
            const price = billing === "annual" ? p.annualMonthly : p.monthly;
            return (
              <div key={p.id} className={`v3-plan${p.featured ? " featured" : ""}`}>
                <div>
                  <div className="v3-between">
                    <h3 style={{ fontSize: 16 }}>{p.name}</h3>
                    {p.featured ? <span className="v3-tag ok">Most teams</span> : null}
                  </div>
                  <p className="v3-small" style={{ marginTop: 5 }}>{p.who}</p>
                </div>
                <div>
                  <span className="v3-plan-price">${price.toLocaleString()}</span>
                  <span className="v3-small"> {p.id === "enterprise" ? "/mo, from" : "/mo"}</span>
                </div>
                <ul>{p.limits.map((l) => <li key={l}>{l}</li>)}</ul>
                <Link
                  href={p.id === "enterprise" ? "/proto-v3/app/settings" : "/proto-v3/onboarding"}
                  className={`v3-btn v3-btn-sm ${p.featured ? "v3-primary" : "v3-ghost"}`}
                >
                  {p.cta}
                </Link>
              </div>
            );
          })}
        </div>

        <div className="v3-card v3-card-p" style={{ marginTop: 18 }}>
          <Eyebrow>In every plan</Eyebrow>
          <div className="v3-included" style={{ marginTop: 14 }}>
            {INCLUDED.map((f) => <div key={f}><Check size={15} />{f}</div>)}
          </div>
          <hr className="v3-rule" style={{ margin: "18px 0 14px" }} />
          <p className="v3-small">
            Nothing security-relevant is held back from a smaller plan. Over a limit we email you
            before we charge you — extra repository $39/mo, extra 100 pull-request audits $49.
          </p>
        </div>

        <div style={{ marginTop: 18 }}><Sizer /></div>
      </div>

      <div className="v3-band">
        <div className="v3-shell" style={{ padding: "24px 0", fontSize: 13, color: "var(--muted-navy)" }}>
          <div className="v3-between">
            <span>Prototype · demo data only · nothing here calls a real service</span>
            <Link href="/proto-v3/app">Open the product <ArrowRight size={13} style={{ verticalAlign: "-2px" }} /></Link>
          </div>
        </div>
      </div>
    </>
  );
}

/**
 * The hero diagram. It draws the actual claim — one repository becomes a map of
 * entries, identity and data — rather than decorating the page with a radar.
 */
function RepositoryMap() {
  const files = [
    { y: 46, label: "route.ts" },
    { y: 136, label: "schema.ts" },
    { y: 226, label: "middleware.ts" },
  ];
  const outs = [
    { y: 60, label: "63 entries" },
    { y: 140, label: "3 identity boundaries" },
    { y: 220, label: "24 data assets" },
  ];

  return (
    <div className="v3-map" aria-label="One repository becomes a map of entries, identity and data">
      <svg viewBox="0 0 440 300" role="img">
        {files.map((f) => (
          <g key={f.label}>
            <rect x="4" y={f.y} width="104" height="30" rx="4" fill="none" stroke="var(--line-navy)" />
            <text x="18" y={f.y + 19}>{f.label}</text>
            <path className="edge" d={`M108 ${f.y + 15} C 160 ${f.y + 15}, 165 150, 208 150`} />
          </g>
        ))}
        <circle cx="216" cy="150" r="7" fill="var(--bronze-l)" />
        <circle cx="216" cy="150" r="15" fill="none" stroke="var(--bronze-l)" strokeOpacity=".35" />
        {outs.map((o, i) => (
          <g key={o.label}>
            <path className={`edge${i === 2 ? " hot" : ""}`} d={`M224 150 C 268 150, 272 ${o.y + 14}, 316 ${o.y + 14}`} />
            <text className="lbl" x="324" y={o.y + 18}>{o.label}</text>
          </g>
        ))}
        <text x="4" y="286">your repository</text>
        <text className="lbl" x="324" y="286">what it declares</text>
      </svg>
    </div>
  );
}

/** Which plan fits — two inputs, because those are the two that drive our cost. */
function Sizer() {
  const { billing } = useStore();
  const [lines, setLines] = useState(140);
  const [prs, setPrs] = useState(80);

  const plan = useMemo(() => {
    if (lines <= 50 && prs <= 30) return PLANS[0];
    if (lines <= 250 && prs <= 200) return PLANS[1];
    if (lines <= 1500 && prs <= 750) return PLANS[2];
    return PLANS[3];
  }, [lines, prs]);

  const price = billing === "annual" ? plan.annualMonthly : plan.monthly;

  return (
    <div className="v3-card">
      <div className="v3-hd">
        <h3 className="v3-eyebrow">Which plan fits</h3>
        <span className="v3-small">Move the sliders to your codebase.</span>
      </div>
      <div className="v3-card-p v3-grid-2" style={{ alignItems: "center" }}>
        <div className="v3-stack" style={{ gap: 16 }}>
          <div className="v3-field">
            <label htmlFor="v3-lines">Lines of code <span className="v3-mono">{lines}k</span></label>
            <input id="v3-lines" type="range" min={10} max={2000} step={10} value={lines} onChange={(e) => setLines(+e.target.value)} />
          </div>
          <div className="v3-field">
            <label htmlFor="v3-prs">Pull requests a month <span className="v3-mono">{prs}</span></label>
            <input id="v3-prs" type="range" min={5} max={900} step={5} value={prs} onChange={(e) => setPrs(+e.target.value)} />
          </div>
        </div>
        <div style={{ borderLeft: "1px solid var(--line)", paddingLeft: 24 }}>
          <Eyebrow>Recommended</Eyebrow>
          <p className="v3-serif" style={{ fontSize: 28, margin: "6px 0 4px" }}>{plan.name}</p>
          <p className="v3-small">{plan.who}</p>
          <p className="v3-serif" style={{ marginTop: 12, fontSize: 21 }}>
            ${price.toLocaleString()}<span className="v3-small">/mo</span>
          </p>
        </div>
      </div>
    </div>
  );
}
