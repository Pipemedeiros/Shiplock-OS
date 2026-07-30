import type { Metadata } from "next";
import Link from "next/link";
import { OAuthButtons } from "@/components/marketing/oauth-buttons";
import { ProximityText, Reveal, RevealList, ShinyText, SpotlightCard } from "@/components/d/bits";
import { Seal } from "@/components/d/Seal";
import { LockMark } from "@/components/d/Brand";
import { ProvingAnimation } from "@/components/d/ProvingAnimation";
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
        Representative output: severity, the asset, and a remediation you can merge. Passing
        checks are shown alongside failing ones — a control that was verified is a result.
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
      "Session handling, token configuration, rate limiting on the auth endpoints, and whether privileged routes actually verify authorisation rather than only authentication.",
  },
  {
    name: "Data exposure",
    blurb:
      "Whether row-level security, column grants and storage policies refuse the queries they are meant to refuse. This is the surface behind nearly every documented breach of an AI-built application.",
  },
  {
    name: "Configuration",
    blurb:
      "Credential handling, response headers, source maps, CI workflow permissions, and dependencies carrying published advisories.",
  },
  {
    name: "Injection & logic",
    blurb:
      "Untrusted input reaching a query or a template, mass assignment on write endpoints, and server-side request forgery through user-supplied URLs.",
  },
];

const TRUST_LINE =
  "Onboarding takes your project URL and the publishable key your client already ships to every visitor. Deeper checks use a read-only Management API grant you authorise over OAuth and can revoke at any time — the transport refuses anything that is not a single SELECT. Secret keys are never stored; if one is submitted it is flagged and discarded. Autonomous remediation is off by default and, when enabled, is bounded to reversible actions with the inverse computed before the change.";

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
              <Link href="/coverage">Scope</Link>
              <Link href="/owasp">OWASP</Link>
              <Link href="/incidents">Incidents</Link>
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
                ShipLock audits your live Supabase project — row-level security, auth
                configuration, storage, grants, dependencies and the routes that reach them — on
                every pull request rather than once a quarter. Tenant-isolation failures are
                demonstrated against a disposable copy of your schema, not inferred from reading
                policy text. Findings arrive as migration pull requests you review and merge.
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
                <div className="dxd-proof-label">Per month. A comparable application security assessment runs $50,000 and is performed once a year.</div>
              </div>
              <div>
                <div className="dxd-proof-num">16</div>
                <div className="dxd-proof-label">Checks across four surfaces — access control, data exposure, configuration, injection — re-run on every pull request.</div>
              </div>
              <div>
                <div className="dxd-proof-num">90<em>s</em></div>
                <div className="dxd-proof-label">To first findings. The inputs are your project URL and the publishable key your client already ships.</div>
              </div>
              <div>
                <div className="dxd-proof-num">0</div>
                <div className="dxd-proof-label">Dashboards to watch. Findings are diffed against the previous pass by stable identifier, so you hear from us on change, not on recurrence.</div>
              </div>
            </RevealList>
          </div>

          <Reveal>
            <p className="dxd-eyebrow" style={{ marginTop: 56 }}>The watch, in practice</p>
            <h2 className="dxd-h2">A point-in-time assessment expires at your next deploy.</h2>
            <p className="dxd-lede">
              Security posture is a property of the current commit, not of the codebase in general.
              One agent-authored migration can drop a policy that a report from last week certified.
              So the audit re-runs on a schedule and on every pull request, and each pass is diffed
              against the last — you are alerted on new findings, not re-alerted on known ones.
            </p>
          </Reveal>

          <div className="dxd-watchrows">
            <RevealList step={90}>
              <div className="dxd-watchrow">
                <h3>Every pull request, re-audited</h3>
                <p>
                  One GitHub App installation. Every pull request is re-scanned before merge:
                  committed credentials, dependencies with known advisories, workflow permissions,
                  and changes to the code paths that enforce access control.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>Deep audits on schedule, critical checks hourly</h3>
                <p>
                  A full sixteen-check pass every 48 hours. Between them, an hourly pass covering
                  the four failures that appear without a deploy — RLS switched off, a bucket made
                  public, credentials exposed at the origin, a secret key in use.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>A live edge at your front door</h3>
                <p>
                  A middleware snippet mirrors auth-route metadata to us and fails open by
                  construction: if we are slow or down, your request proceeds. Credential stuffing
                  and enumeration are scored per source, and a source is blocked only on
                  unambiguous signal — false positives here lock out paying users, so the
                  threshold is deliberately conservative.
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
                A shareable page showing which controls are assessed against your project, the
                cadence, and when each last ran. It publishes posture and timestamps, never your
                specific findings — a report that enumerated your open issues would be a target
                map. It is not a SOC 2 report and does not substitute for one; it is a verifiable
                answer for the period before you have one.
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
            <h2 className="dxd-h2">Three reasons this becomes urgent before anything leaks.</h2>
            <p className="dxd-lede">
              You likely know roughly where your gaps are. What changes once you have real users is
              not the technical risk — it is that the risk acquires a counterparty, a deadline and a
              regulator.
            </p>
          </Reveal>
          <div className="dxd-stakes">
            <RevealList step={90}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">I · THE DEAL</span>
                <h3>The first serious customer asks you to prove it.</h3>
                <p>
                  Not a breach — a security questionnaire. Procurement wants to know how access is
                  controlled, who verifies it, and how often. SOC 2 Type I answers that for
                  $20,000 and three months. Before that, a live posture report showing the controls
                  assessed and their last run is a defensible answer rather than an assurance.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">II · THE BLIND SPOT</span>
                <h3>The dangerous policy looks exactly like a safe one.</h3>
                <p>
                  A table with RLS enabled and a <code>USING (true)</code> policy refuses anonymous
                  reads, so it passes any external probe holding only a publishable key. Every
                  authenticated user still reads every row. This is the most common critical
                  finding on Supabase, and detecting it requires evaluating the policy as a
                  signed-in caller — which is what the sandbox exists to do.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">III · THE LEGAL WEIGHT</span>
                <h3>Customer data makes it a legal matter.</h3>
                <p>
                  Once personal data is exposed, obligations attach regardless of company size:
                  notification to affected users, response to privacy regulators within statutory
                  deadlines, and civil liability. None of these scale down because you are a team
                  of two.
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

        {/* ── 3b · Sandboxed exploitation ─────────────────────────────── */}
        <section className="dxd-section" id="proving">
          <Reveal>
            <p className="dxd-eyebrow">Proof, not inference</p>
            <h2 className="dxd-h2">We exploit a copy of your schema, never your app.</h2>
            <p className="dxd-lede">
              Reading a policy tells you what it should do. Running against it tells you what it
              does. For tenant isolation — the failure where one signed-in customer reaches
              another&apos;s rows — we settle the question by trying it, inside an environment
              built for the purpose and destroyed afterwards.
            </p>
          </Reveal>

          <Reveal>
            <ProvingAnimation />
          </Reveal>

          <Reveal>
            <p className="dxd-lede" style={{ marginTop: 22 }}>
              The arena holds your schema and policies and none of your data. The accounts in it
              are synthetic, so there is no row belonging to a real person for anything to reach.
              A control query runs first: if the arena cannot return the caller&apos;s own row,
              the result is discarded rather than reported as clean — a broken sandbox that says
              &ldquo;no leak&rdquo; is worse than no sandbox at all.
            </p>
            <p className="dxd-lede" style={{ marginTop: 14 }}>
              Where the fixed probe finds nothing, a reasoning agent proposes further queries.
              It contributes ideas, never authority: every statement it composes is checked by a
              deterministic guard that permits read-only queries inside the disposable schema and
              refuses everything else, and each attempt — including the refused ones — is kept as
              evidence. We never point it at anything you operate.{" "}
              <Link href="/coverage">The full scope, including where each capability stops →</Link>
            </p>
          </Reveal>
        </section>

        {/* ── 4 · Fixes ───────────────────────────────────────────────── */}
        <section className="dxd-section" id="fixes">
          <Reveal>
            <p className="dxd-eyebrow">The handoff</p>
            <h2 className="dxd-h2">Remediation is a diff, and the diff is yours to approve.</h2>
            <p className="dxd-lede">
              Each finding ships with its remediation. Schema and access-control changes open a
              migration pull request on a new branch — you review it, edit it, merge it, and your
              own pipeline applies it. Application logic is never machine-authored; those open as
              draft pull requests for you or your coding agent to finish. Nothing is applied
              silently, and every action carries a stored inverse.
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
                Opened as a pull request against a new branch, never merged by us. Auth, RLS and
                schema changes stay under your review by design — the blast radius of a wrong
                policy is your entire user base.
              </p>
            </div>
          </Reveal>
          <Reveal>
            <div className="dxd-surface" style={{ maxWidth: 640, margin: "20px auto 0" }}>
              <p className="dxd-eyebrow" style={{ margin: "0 0 8px" }}>Or don&apos;t leave your editor</p>
              <h3 style={{ margin: "0 0 8px", fontSize: 18 }}>Connect ShipLock to your coding agent.</h3>
              <p style={{ margin: 0, fontSize: 13.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
                ShipLock exposes its findings over MCP. Add it to Claude Code, Cursor or Codex and
                your agent pulls open findings and their remediations into context, then writes the
                changes in your working tree — still a diff you review before it lands.
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
            For scale: a first-year SOC 2 runs $20,000–$60,000 across the audit, the compliance
            tooling and your own engineering time. It answers a different question — organisational
            control design — on a longer clock. This is the technical layer underneath it, and the
            evidence trail it produces is the kind an auditor later asks for.
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
            A one-time scan characterises a single commit. A retainer characterises a moving
            codebase: every pull request, hourly on the fast-moving checks, and in full depth every
            48 hours.
          </p>
        </section>

        {/* ── 6 · Honest limits, then the door ────────────────────────── */}
        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">What we won&apos;t promise</p>
            <h2 className="dxd-h2">No control set eliminates risk. Ours reduces a specific, well-understood part of it.</h2>
            <p className="dxd-lede">
              Breaches of applications at your stage are overwhelmingly not novel: a missing
              access-control rule, an exposed credential, an unpatched dependency, an unauthenticated
              route. That class is enumerable, testable and closeable, and it is the class we
              address — continuously, so a regression is caught by the next pass rather than by a
              customer. Targeted attacks, insider access and flaws in your own business logic are
              outside it, and we say so in each report rather than at the end.
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
              Where a check does not apply or could not run, the report says so explicitly. An
              absent result is never rendered as a pass — a repository we failed to read and a
              repository with nothing to find produce different output, because treating unknown as
              safe is how assessments mislead. For what no scanner can evaluate — your authorisation
              logic, your business rules — we supply the review prompts to audit it yourself.
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
            <Link href="/coverage">Scope</Link> · <Link href="/owasp">OWASP</Link> ·{" "}
            <Link href="/incidents">Incidents</Link> · <Link href="/accessibility">Accessibility</Link> ·{" "}
            <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link> ·{" "}
            <Link href="/dashboard-demo">Product preview →</Link> · support@shiplock.dev
          </span>
        </footer>
      </div>
    </main>
  );
}
