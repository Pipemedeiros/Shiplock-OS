import type { Metadata } from "next";
import Link from "next/link";
import { OAuthButtons } from "@/components/marketing/oauth-buttons";
import { ProximityText, Reveal, RevealList, ShinyText, SpotlightCard } from "@/components/d/bits";
import { Seal } from "@/components/d/Seal";
import { LockMark } from "@/components/d/Brand";
import { TrafficDefense } from "@/components/d/TrafficDefense";
import { RiskHonesty } from "@/components/d/RiskHonesty";
import { FixFlow } from "@/components/d/FixFlow";
import { PLANS, isPlanConfigured } from "@/lib/plans";

// Real landing page, Design D visuals. Same reason as before this reskin:
// no dynamic data here, so Next would otherwise statically prerender at
// build time — before middleware.ts's per-request CSP nonce exists —
// silently blocking every client script. Force dynamic rendering to keep
// this page's script nonces in sync with the header middleware sets for
// each request.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  // Landing keeps the layout's default title (no template suffix doubling).
  title: { absolute: "ShipLock — Continuous security monitoring for Supabase apps" },
  description:
    "Continuous security monitoring for Supabase apps in production. Permissive RLS policies, exposed keys, public buckets and vulnerable dependencies — found continuously, fixed by pull request, and provable with a live report when a customer asks. $49/month, 7 days free.",
};

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "dxd-chip-critical",
  High: "dxd-chip-high",
  Medium: "dxd-chip-medium",
  Pass: "dxd-chip-verified",
};

const EXAMPLE_FINDINGS = [
  { severity: "Critical", text: "storage bucket 'user-uploads' is publicly readable" },
  { severity: "High", text: "RLS disabled on table 'invoices'" },
  { severity: "Medium", text: "no rate limit on /auth/v1/token" },
  { severity: "Pass", text: "service role key not exposed to client" },
];

function ExampleAuditPanel() {
  return (
    <div className="dxd-surface" style={{ width: "100%", maxWidth: 420 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 16 }}>
        <p className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", textTransform: "uppercase", letterSpacing: "0.1em", margin: 0 }}>
          Example audit — anonymized
        </p>
        <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-verified)", background: "var(--d-porcelain)", padding: "2px 8px", borderRadius: 4, display: "inline-flex", alignItems: "center", gap: 5 }}>
          <span className="dxd-livedot" style={{ fontSize: 8 }}>●</span> on watch
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 20 }}>
        <span className="dxd-serif" style={{ fontSize: 44, fontWeight: 700 }}>4</span>
        <span style={{ fontSize: 14, color: "var(--d-muted)" }}>open findings · 1 critical</span>
      </div>

      <div className="dxd-scanwrap dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12.5 }}>
        <span className="dxd-scanline" aria-hidden="true" />
        {EXAMPLE_FINDINGS.map((f) => (
          <div
            key={f.text}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              borderRadius: 8,
              border: "1px solid var(--d-line)",
              background: "var(--d-porcelain)",
              padding: "8px 12px",
            }}
          >
            <span className={`dxd-chip ${SEVERITY_STYLES[f.severity]}`}>{f.severity}</span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--d-ink)" }}>
              {f.text}
            </span>
          </div>
        ))}
      </div>

      <p style={{ marginTop: 16, fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted)" }}>
        A sample of what lands in your dashboard on retainer — every finding, and a fix
        you can merge for each.
      </p>
    </div>
  );
}

// Four attack surfaces, described by the risk each one carries — deliberately
// not a mechanism-by-mechanism list of how the scanner probes for them. What
// we cover is public; how we detect it is the product. Coverage detail, mapped
// to a real standard, lives on /owasp.
const SURFACES: { name: string; blurb: string }[] = [
  {
    name: "Auth & access",
    blurb:
      "Who can sign in, hammer your endpoints, or reach admin routes they were never meant to see.",
  },
  {
    name: "Data exposure",
    blurb:
      "Whether your database and storage answer questions they should refuse — the failure behind almost every AI-built app breach on record.",
  },
  {
    name: "Configuration",
    blurb:
      "The settings, keys, dependencies, and headers that quietly decide how protected you actually are.",
  },
  {
    name: "Injection & logic",
    blurb:
      "Whether crafted input or a careless endpoint can make your app do things you never wrote.",
  },
];

const TRUST_LINE =
  "We only ever ask for your app's public key, plus an optional public URL — never a credential beyond that key, the same one your own frontend already exposes to every visitor. No admin tokens, and we never write to your production database.";

export default function LandingPage() {
  // Only advertise terms that actually have a Stripe price behind them.
  // Monthly always shows — it's the plan the product has always had; the
  // prepaid terms stay hidden until the owner creates those prices, so no one
  // can click through to a dead checkout.
  const plans = PLANS.filter((p) => p.id === "monthly" || isPlanConfigured(p));

  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/" className="dxd-wordmark">
              <span className="dxd-wordmark-lock">
                <LockMark size={19} />
              </span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <a href="#watch">The watch</a>
              <a href="#fixes">Fixes</a>
              <Link href="/owasp">Coverage</Link>
              <Link href="/incidents">Real incidents</Link>
              <a href="#pricing">Pricing</a>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>

          <header className="dxd-hero">
            <div>
              <p className="dxd-eyebrow">Security on retainer · Supabase apps in production</p>
              <h1 className="dxd-display">
                <ProximityText text="One permissive policy exposes every row." />
                <br />
                <em>
                  <ShinyText>We find it, fix it, and keep proving it.</ShinyText>
                </em>
              </h1>
              <p className="dxd-lede">
                ShipLock runs an auditor&apos;s depth against your live Supabase project —
                continuously, not once. Findings come back as pull requests you merge. And when a
                customer asks whether you&apos;re secure, you have a live report to send them
                instead of a promise.
              </p>
              <div className="dxd-hero-actions">
                <a href="#get-started" className="dxd-btn dxd-btn-paper">
                  Start the audit
                </a>
                <a href="#pricing" className="dxd-btn dxd-btn-ghost">
                  $49/month · 7 days free
                </a>
              </div>
            </div>

            <div aria-label="An example audit result">
              <ExampleAuditPanel />
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        {/* ── 2 · The watch ─────────────────────────────────────────────
            Proof band, the live edge, and the three monitoring triggers,
            folded into one section. This is the differentiator against
            running a one-shot scanner yourself, so it demonstrates rather
            than argues. */}
        <section className="dxd-section" id="watch" style={{ paddingTop: 56 }}>
          <div className="dxd-proof">
            <RevealList step={80}>
              <div>
                <div className="dxd-proof-num">$49</div>
                <div className="dxd-proof-label">The depth of a $50,000 enterprise audit — running continuously, for $49 a month.</div>
              </div>
              <div>
                <div className="dxd-proof-num">16</div>
                <div className="dxd-proof-label">Checks across four attack surfaces, re-run on every pull request.</div>
              </div>
              <div>
                <div className="dxd-proof-num">90<em>s</em></div>
                <div className="dxd-proof-label">From one paste to your first findings — just a URL and the public key your app already ships.</div>
              </div>
              <div>
                <div className="dxd-proof-num">0</div>
                <div className="dxd-proof-label">Consoles to babysit. You only hear from us when something new appears — silence means safe.</div>
              </div>
            </RevealList>
          </div>

          <Reveal>
            <p className="dxd-eyebrow" style={{ marginTop: 56 }}>The watch, in practice</p>
            <h2 className="dxd-h2">A scan is a photograph. Your app doesn&apos;t hold still.</h2>
            <p className="dxd-lede">
              One prompt to your coding agent tomorrow can quietly undo today&apos;s fix — which is
              why a point-in-time report, however deep, expires on your next change. So we re-check
              continuously, and speak up only when something actually changed.
            </p>
          </Reveal>

          <div className="dxd-watchrows">
            <RevealList step={90}>
              <div className="dxd-watchrow">
                <h3>Every pull request, re-audited</h3>
                <p>
                  Connect your GitHub repo once. Every pull request is re-scanned automatically —
                  new secrets, vulnerable dependencies, and risky changes caught before they merge.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>Deep audits on schedule, critical checks hourly</h3>
                <p>
                  A full sixteen-check pass re-runs every 48 hours; a lightweight critical pass runs
                  every hour, watching the fastest-moving risks.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>A live edge at your front door</h3>
                <p>
                  Credential-stuffing bots and scanners are knocking right now. One small file — it
                  fails open, always — mirrors your auth routes to us, and once an attack is
                  unmistakable, that source gets shut out. Never on a hunch, so a real customer
                  never hits a wall.
                </p>
              </div>
            </RevealList>
          </div>

          <Reveal delay={80}>
            <div style={{ marginTop: 30 }}>
              <TrafficDefense />
            </div>
          </Reveal>

          <Reveal>
            <div className="dxd-surfaces" style={{ marginTop: 40 }}>
              {SURFACES.map((s) => (
                <SpotlightCard className="dxd-surface" key={s.name}>
                  <h3>{s.name}</h3>
                  <p>{s.blurb}</p>
                </SpotlightCard>
              ))}
            </div>
            <p className="dxd-rescan-note" style={{ marginTop: 18 }}>
              Sixteen checks span those four surfaces, mapped to the OWASP Top 10:2025 —{" "}
              <Link href="/owasp">including what we can&apos;t catch, named honestly →</Link>
            </p>
          </Reveal>

          <div className="dxd-trust">
            <div>
              <h3>Something to send when they ask.</h3>
              <p>
                Turn on a public report and you get a live page showing which checks run against
                your project, when they last ran, and what&apos;s covered — updated continuously,
                not a PDF that expired the day it was written. It shows posture and cadence, never
                your specific findings. It is not a SOC 2 report and never claims to be; it&apos;s
                the honest answer for the eighteen months before you need one.
              </p>
              <p style={{ marginTop: 12 }}>{TRUST_LINE}</p>
            </div>
            <Seal state="intact" size={148} />
          </div>
        </section>

        {/* ── 3 · The stakes ──────────────────────────────────────────── */}
        <section className="dxd-section" id="stakes">
          <Reveal>
            <p className="dxd-eyebrow">Why this matters now</p>
            <h2 className="dxd-h2">The bill arrives before the breach does.</h2>
            <p className="dxd-lede">
              You already know roughly where the gaps are. What changes once you have real users
              isn&apos;t the risk — it&apos;s that the risk starts having a due date.
            </p>
          </Reveal>
          <div className="dxd-stakes">
            <RevealList step={90}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">I · THE DEAL</span>
                <h3>The first serious customer asks you to prove it.</h3>
                <p>
                  Not a breach — a questionnaire. Someone&apos;s procurement team wants to know how
                  access is controlled and who checks. SOC 2 answers that for $20,000 and three
                  months. Until you&apos;re there, the honest answer is a live report showing what
                  runs against your project and when it last ran.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">II · THE BLIND SPOT</span>
                <h3>The dangerous policy looks exactly like a safe one.</h3>
                <p>
                  A table with RLS enabled and <code>USING (true)</code> refuses anonymous reads —
                  so from outside it passes. Every signed-in user can still read every row. It is
                  the most common real Supabase critical, and it is invisible to anything checking
                  from the outside with an anon key.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">III · THE LEGAL WEIGHT</span>
                <h3>Customer data makes it a legal matter.</h3>
                <p>
                  The moment real people&apos;s data leaks, you owe things: breach notifications to
                  affected users, answers to privacy regulators, and potentially damages —
                  customers can and do sue over exposed personal data.
                </p>
              </SpotlightCard>
            </RevealList>
          </div>
          <Reveal>
            <p className="dxd-mono" style={{ marginTop: 28, fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)", borderLeft: "2px solid var(--d-bronze)", paddingLeft: 16 }}>
              This isn&apos;t hypothetical. CVE-2025-48757: 170+ live apps built with an AI builder
              were found serving names, emails, and financial data to anyone who asked — one
              missing database rule, rated CVSS 9.3.{" "}
              <Link href="/incidents" style={{ color: "var(--d-ink)" }}>
                We wrote up what actually happened →
              </Link>
            </p>
          </Reveal>
        </section>

        {/* ── 4 · Fixes ───────────────────────────────────────────────── */}
        <section className="dxd-section" id="fixes">
          <Reveal>
            <p className="dxd-eyebrow">The handoff</p>
            <h2 className="dxd-h2">Findings arrive as fixes — one button, fully reviewable.</h2>
            <p className="dxd-lede">
              Every finding comes with an exact fix and a button to apply it. Database and
              access-control changes open a migration pull request you review, edit, and merge —
              your own deploy applies it. We never write to your database directly. Nothing about a
              fix is silent; each one is a diff you approve.
            </p>
          </Reveal>
          <Reveal>
            <FixFlow />
          </Reveal>
          <Reveal>
            <div className="dxd-surface" style={{ maxWidth: 640, margin: "28px auto 0" }}>
              <p className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", textTransform: "uppercase", letterSpacing: "0.1em", margin: "0 0 12px" }}>
                Example fix — anonymized · one reviewable PR per finding
              </p>
              <p className="dxd-mono" style={{ fontSize: 12.5, lineHeight: 1.7, margin: 0, color: "var(--d-ink)", background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8, padding: "14px 16px", overflowX: "auto" }}>
                supabase/migrations/…_shiplock_enable_rls_invoices.sql<br />
                ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;<br />
                CREATE POLICY owner_only ON invoices<br />
                &nbsp;&nbsp;USING (auth.uid() = user_id);
              </p>
              <p style={{ marginTop: 14, fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted)" }}>
                Opened as a pull request you read, edit, and merge — never applied to your
                production database by us. Auth, RLS, and data changes stay in your hands, by design.
              </p>
            </div>
          </Reveal>
          <Reveal>
            <div className="dxd-surface" style={{ maxWidth: 640, margin: "20px auto 0" }}>
              <p className="dxd-eyebrow" style={{ margin: "0 0 8px" }}>Or don&apos;t leave your editor</p>
              <h3 style={{ margin: "0 0 8px", fontSize: 18 }}>Connect ShipLock to your coding agent.</h3>
              <p style={{ margin: 0, fontSize: 13.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
                Add ShipLock to Claude Code, Cursor, or Codex. Your agent pulls your open findings
                into context and writes the fixes right where you work — each one a diff you review
                before it lands. The whole audit, in the tool you already build in.
              </p>
            </div>
          </Reveal>
        </section>

        {/* ── 5 · Pricing ─────────────────────────────────────────────── */}
        <section className="dxd-section" id="pricing">
          <p className="dxd-eyebrow">Terms</p>
          <h2 className="dxd-h2">One engagement. Three ways to pay for it.</h2>
          <p className="dxd-lede" style={{ marginBottom: 8 }}>
            The same product on every term — nothing is held back on the monthly plan. Longer terms
            are simply cheaper, paid once, with no auto-renewal and no cancellation fee.
          </p>
          <p className="dxd-lede" style={{ marginBottom: 8 }}>
            For scale: a first-year SOC 2 runs $20,000–$60,000 once you count the audit, the
            tooling, and your own time. That answers a different question, for a bigger company,
            on a longer clock. This is what you run in the meantime — and what makes that audit
            less painful when it does arrive.
          </p>
          <div className="dxd-pricing">
            {plans.map((plan) => (
              <SpotlightCard
                className={`dxd-price-card${plan.featured ? " dxd-featured" : ""}`}
                key={plan.id}
              >
                <p className="dxd-price-name">{plan.name}</p>
                <p className="dxd-price dxd-serif">
                  {plan.price}
                  <span>{plan.per}</span>
                </p>
                <p className="dxd-price-tag">{plan.tagline}</p>
                <ul>
                  {plan.features.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
                <a href="#get-started" className={plan.featured ? "dxd-btn" : "dxd-btn dxd-btn-ghost"}>
                  {plan.cta}
                </a>
              </SpotlightCard>
            ))}
          </div>
          <p className="dxd-rescan-note">
            A one-time scan answers &ldquo;am I OK today?&rdquo; The retainer answers &ldquo;am I
            still OK?&rdquo; — every pull request, every hour, and in full depth every 48 hours.
          </p>
        </section>

        {/* ── 6 · Honest limits, then the door ────────────────────────── */}
        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">What we won&apos;t promise</p>
            <h2 className="dxd-h2">No one can make your app unhackable. We&apos;ll never pretend otherwise.</h2>
            <p className="dxd-lede">
              Every tool promising &ldquo;100% protected&rdquo; is selling you something, and some
              part of you already knows it. What&apos;s actually true is quieter and more useful:
              almost every app that gets breached is breached through a known, ordinary, closeable
              hole. We close those, we watch them stay closed, and we turn away the automated
              attacks hitting your door — which moves you from the app that gets breached to the one
              that isn&apos;t worth the effort.
            </p>
          </Reveal>
          <Reveal delay={80}>
            <div style={{ marginTop: 30 }}>
              <RiskHonesty />
            </div>
          </Reveal>
          <Reveal delay={120}>
            <p
              className="dxd-mono"
              style={{
                marginTop: 36,
                fontSize: 12.5,
                lineHeight: 1.75,
                color: "var(--d-ink)",
                borderLeft: "2px solid var(--d-bronze)",
                paddingLeft: 16,
                maxWidth: 720,
              }}
            >
              And we tell you what we <em>can&apos;t</em> see. Your business logic, the auth checks
              inside your own code — no scanner reads those. Rather than quietly leaving them off
              the report, we hand you the exact prompts to audit them yourself. The honesty is the
              product.
            </p>
          </Reveal>

          <Reveal delay={120}>
            <div style={{ marginTop: 56, borderTop: "1px solid var(--d-line)", paddingTop: 40 }}>
              <p className="dxd-eyebrow">Get started</p>
              <h2 className="dxd-h2">Connect the project. Get the first findings in 90 seconds.</h2>
              <p className="dxd-lede">
                Sign in, start the trial — 7 days free before the first charge — then paste your
                Supabase URL and anon key. Nothing we ask for is a credential beyond the public key
                your frontend already ships. The first audit runs immediately.
              </p>
            </div>
          </Reveal>
          <Reveal delay={160}>
            <div style={{ marginTop: 28, display: "flex", justifyContent: "center" }}>
              <OAuthButtons />
            </div>
          </Reveal>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span> On retainer since today.
          </span>
          <span>
            <Link href="/owasp">Coverage</Link> · <Link href="/incidents">Real incidents</Link> ·{" "}
            <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link> ·{" "}
            <Link href="/dashboard-preview">Product preview →</Link> · support@shiplock.dev
          </span>
        </footer>
      </div>
    </main>
  );
}
