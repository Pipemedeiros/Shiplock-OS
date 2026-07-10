"use client";

// DIRECTION D · ON RETAINER — landing.
// Bet: premium relief, with receipts. The customer built something that
// earns; they're technical enough to read the evidence and tired enough
// not to want to. Tone: a serious firm taking over a burden. No
// translation layer, no theater — substance, shown, never required.

import Link from "next/link";
import {
  CHECKS,
  DISCLAIMER,
  HOW_IT_WORKS,
  MOCK_PROJECT,
  PRICING,
  STACK_SPEAKS,
  SURFACES,
  TRUST_LINE,
} from "../_shared/data";
import { Receipt, receiptFor } from "./Receipt";
import { Seal } from "./Seal";
import { Reveal, ShinyText, SpotlightCard } from "./bits";
import { LockMark } from "./Brand";

export default function RetainerLanding() {
  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/design/d" className="dxd-wordmark">
              <span className="dxd-wordmark-lock">
                <LockMark size={19} />
              </span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <a href="#method">The method</a>
              <a href="#pricing">Pricing</a>
              <Link href="/design/d/onboarding" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>

          <header className="dxd-hero">
            <div>
              <p className="dxd-eyebrow">
                Security on retainer · for apps that earn
              </p>
              <h1 className="dxd-display">
                You built something worth protecting.
                <br />
                <em>
                  <ShinyText>We carry the worry.</ShinyText>
                </em>
              </h1>
              <p className="dxd-lede">
                ShipLock runs the checks a $50,000 enterprise audit would —
                continuously, against your live app — and files a receipt for
                every one. Built for founders who shipped with AI, found paying
                users, and would rather not bet the business on their own
                security guesswork.
              </p>
              <div className="dxd-hero-actions">
                <Link href="/design/d/onboarding" className="dxd-btn dxd-btn-paper">
                  Run the first audit — free
                </Link>
                <a href="#method" className="dxd-btn dxd-btn-ghost">
                  The method
                </a>
              </div>
            </div>

            <div aria-label="A sample verification receipt">
              <Receipt
                label="Verification receipt · sample"
                refNo="№ 2026-1284"
                data={receiptFor(1, "Row-level security", false)}
                stampLeft={`${MOCK_PROJECT.appUrl}`}
                stampRight="verified 14:02:04 UTC"
              />
              <p
                className="dxd-mono"
                style={{
                  fontSize: 11.5,
                  color: "var(--d-muted-light)",
                  margin: "14px 4px 0",
                  lineHeight: 1.6,
                }}
              >
                Every check files one of these. You&apos;ll rarely read them —
                they exist so you don&apos;t have to.
              </p>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        <section className="dxd-section" id="stakes">
          <Reveal>
            <p className="dxd-eyebrow">Why this matters</p>
            <h2 className="dxd-h2">
              One open table can undo two years of work.
            </h2>
            <p className="dxd-lede">
              Your app has paying customers now. That changes what a security
              mistake costs — it stops being embarrassing and starts being
              expensive. Three ways, specifically:
            </p>
          </Reveal>
          <div className="dxd-stakes">
            <Reveal delay={0}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">I · THE BREACH</span>
                <h3>Apps get broken through boring doors.</h3>
                <p>
                  Not Hollywood hacking — an unlocked database table, a
                  sign-up flow that never verifies emails, a key sitting in
                  the client bundle. Attackers scan for these automatically,
                  at scale, every day. And it isn&apos;t hypothetical: one
                  disclosed pattern alone (CVE-2025-48757) left a wave of
                  AI-built apps with their customer tables readable by
                  anyone on the internet.
                </p>
              </SpotlightCard>
            </Reveal>
            <Reveal delay={90}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">II · THE LEGAL WEIGHT</span>
                <h3>Customer data makes it a legal matter.</h3>
                <p>
                  The moment real people&apos;s data leaks, you owe things:
                  breach notifications to affected users, answers to privacy
                  regulators, and potentially damages — customers can and do
                  sue over exposed personal data. None of it is priced for a
                  one-person company.
                </p>
              </SpotlightCard>
            </Reveal>
            <Reveal delay={180}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">III · THE TRUST</span>
                <h3>Revenue is trust with a renewal date.</h3>
                <p>
                  People pay you monthly because they assume you&apos;re
                  keeping their data safe. A breach converts your best
                  customers into your loudest churn — refunds, cancellations,
                  and a story about your product you don&apos;t get to edit.
                </p>
              </SpotlightCard>
            </Reveal>
          </div>
          <Reveal>
            <p className="dxd-stake-close">
              You don&apos;t need to be scared of any of this.
              You need someone carrying it.
            </p>
          </Reveal>
        </section>

        <section className="dxd-section" id="method">
          <p className="dxd-eyebrow">The method</p>
          <h2 className="dxd-h2">
            Three steps. Then the weight is ours.
          </h2>
          <div className="dxd-steps">
            {HOW_IT_WORKS.map((s, i) => (
              <div className="dxd-step" key={s.title}>
                <span className="dxd-step-num dxd-serif">No. {i + 1}</span>
                <div>
                  <h3>{s.title}</h3>
                  <p>{s.body}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="dxd-section" id="stack">
          <Reveal>
            <p className="dxd-eyebrow">Your stack</p>
            <h2 className="dxd-h2">Fluent in whatever you built with.</h2>
            <p className="dxd-lede">
              The audit runs against your live app — not your source, not
              your builder — so it works the moment you paste a key,
              whoever wrote the code. Four slots; every provider spoken.
            </p>
          </Reveal>
          <Reveal>
            <div className="dxd-speak" role="table" aria-label="Supported stack, by slot">
              {(
                [
                  {
                    slot: "Builder",
                    names: STACK_SPEAKS.builder,
                    scope: "detected from the app itself — nothing to connect",
                  },
                  {
                    slot: "Database",
                    names: STACK_SPEAKS.database,
                    scope: "the public key your frontend already ships — never more",
                  },
                  {
                    slot: "Host",
                    names: STACK_SPEAKS.host,
                    scope: "optional · read-only, selected projects",
                  },
                  {
                    slot: "Source",
                    names: STACK_SPEAKS.source,
                    scope: "optional · contents: read-only — powers fix PRs",
                  },
                ] as const
              ).map((r) => (
                <div className="dxd-speak-row" role="row" key={r.slot}>
                  <span className="dxd-speak-cat" role="cell">
                    {r.slot}
                  </span>
                  <span className="dxd-speak-names" role="cell">
                    {r.names.map((n, i) => (
                      <span key={n}>
                        {i > 0 && <i aria-hidden="true"> · </i>}
                        {n}
                      </span>
                    ))}
                  </span>
                  <span className="dxd-speak-scope dxd-mono" role="cell">
                    {r.scope}
                  </span>
                </div>
              ))}
            </div>
          </Reveal>
        </section>

        <section className="dxd-section">
          <p className="dxd-eyebrow">Scope of engagement</p>
          <h2 className="dxd-h2">Fifteen checks, named precisely.</h2>
          <p className="dxd-lede" style={{ marginBottom: 8 }}>
            You know your stack. Here is exactly what we hold against it — no
            euphemisms, and every one re-verified continuously.
          </p>
          <div className="dxd-surfaces">
            {SURFACES.map((s) => (
              <SpotlightCard className="dxd-surface" key={s.name}>
                <h3>{s.name}</h3>
                <p>{s.blurb}</p>
                <ul>
                  {CHECKS.filter((c) => c.surface === s.name).map((c) => (
                    <li key={c.id}>
                      <span>
                        {String(c.id).padStart(2, "0")} · {c.name.toLowerCase()}
                      </span>
                      <span>verified hourly</span>
                    </li>
                  ))}
                </ul>
              </SpotlightCard>
            ))}
          </div>

          <div className="dxd-trust">
            <div>
              <h3>Check our work. That&apos;s rather the point.</h3>
              <p>
                {TRUST_LINE} <b>Every claim on your dashboard opens into the
                probe we ran, the answer your app gave, and the verdict.</b>{" "}
                You&apos;re technical enough to audit us — so we make it
                possible, and unnecessary.
              </p>
            </div>
            <Seal state="intact" size={148} />
          </div>
        </section>

        <section className="dxd-section" id="watch">
          <Reveal>
            <p className="dxd-eyebrow">The watch, in practice</p>
            <h2 className="dxd-h2">
              What we monitor — and exactly how.
            </h2>
            <p className="dxd-lede">
              Continuous doesn&apos;t mean a dashboard you have to stare at.
              It means four standing arrangements that run whether or not
              you&apos;re thinking about them.
            </p>
          </Reveal>
          <div className="dxd-watchrows">
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Every deploy, re-audited</h3>
                <p>
                  You ship, we notice. Each deploy triggers the full 15-check
                  audit against the live app before the dust settles —
                  because the most likely moment you break your own security
                  is the moment you change something. <b>Receipt filed every
                  time.</b>
                </p>
              </div>
            </Reveal>
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Deep audits on schedule, critical checks hourly</h3>
                <p>
                  Between deploys, the full audit re-runs on a fixed schedule
                  and the highest-stakes checks re-run every hour — because
                  settings drift, and a table that was locked on Tuesday can
                  quietly come unlocked on Thursday.
                </p>
              </div>
            </Reveal>
            <Reveal>
              <div className="dxd-watchrow">
                <div>
                  <h3>A protective front door</h3>
                  <span className="dxd-soon">joining the retainer</span>
                </div>
                <p>
                  One DNS record points your domain at an edge we operate,
                  and your traffic arrives through it — <b>you never create
                  an account anywhere, never move your app.</b> At that front
                  door, bursts get rate-limited and credential-stuffing bots
                  are recognized and turned away before they ever reach your
                  sign-in page. Every block reversible by you, every event on
                  the log.
                </p>
              </div>
            </Reveal>
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Alerts that respect you</h3>
                <p>
                  You hear from us when something <b>new</b> appears — once,
                  with the brief attached. No weekly digests of nothing, no
                  re-alerts on things you already know. Silence is a
                  statement: everything held.
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        <section className="dxd-section" id="pricing">
          <p className="dxd-eyebrow">Terms</p>
          <h2 className="dxd-h2">One engagement. One number.</h2>
          <div className="dxd-pricing">
            <SpotlightCard className="dxd-price-card">
              <p className="dxd-price-name">The first audit · free</p>
              <p className="dxd-price dxd-serif">{PRICING.free.price}</p>
              <p className="dxd-price-tag">{PRICING.free.tagline}</p>
              <ul>
                {PRICING.free.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
                {PRICING.free.locked.map((f) => (
                  <li key={f} className="dxd-locked">
                    {f} — on retainer
                  </li>
                ))}
              </ul>
              <Link href="/design/d/onboarding" className="dxd-btn dxd-btn-ghost">
                Run the audit
              </Link>
            </SpotlightCard>
            <SpotlightCard className="dxd-price-card dxd-featured">
              <p className="dxd-price-name">The retainer · monitor</p>
              <p className="dxd-price dxd-serif">
                {PRICING.paid.price}
                <span>{PRICING.paid.per}</span>
              </p>
              <p className="dxd-price-tag">
                {PRICING.paid.tagline} Less than an hour of any security
                consultant you could hire.
              </p>
              <ul>
                {PRICING.paid.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <Link href="/design/d/onboarding" className="dxd-btn">
                Put us on retainer
              </Link>
            </SpotlightCard>
          </div>
          <p className="dxd-rescan-note">{PRICING.rescan}</p>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span> On
            retainer since today.
          </span>
          <span>{DISCLAIMER} · rev 7</span>
        </footer>
      </div>
    </main>
  );
}
