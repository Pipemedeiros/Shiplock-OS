import type { Metadata } from "next";
import Link from "next/link";
import { OAuthButtons } from "@/components/marketing/oauth-buttons";
import { ProximityText, Reveal, RevealList, ShinyText, SpotlightCard } from "@/components/d/bits";
import { Seal } from "@/components/d/Seal";
import { LockMark } from "@/components/d/Brand";
import { TrafficDefense } from "@/components/d/TrafficDefense";
import { RiskHonesty } from "@/components/d/RiskHonesty";

// Real landing page, Design D visuals. Same reason as before this reskin:
// no dynamic data here, so Next would otherwise statically prerender at
// build time — before middleware.ts's per-request CSP nonce exists —
// silently blocking every client script. Force dynamic rendering to keep
// this page's script nonces in sync with the header middleware sets for
// each request.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  // Landing keeps the layout's default title (no template suffix doubling).
  title: { absolute: "ShipLock — Continuous security monitoring for AI-built apps" },
  description:
    "Sixteen security checks — RLS, exposed tables, public buckets, leaked secrets — plus a live edge that turns credential-stuffing bots and scanners away from your login, all running continuously against your app. Built for founders who shipped with Lovable, Bolt, v0, or Cursor and found paying users. $49/month, 7 days free.",
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
        A sample of what lands in your dashboard on retainer — every finding, and a
        ready-to-paste fix for each.
      </p>
    </div>
  );
}

const HOW_IT_WORKS = [
  {
    title: "Connect in one paste",
    body: "Your project URL and anon key — the same key your app already shares with every visitor's browser. Add your app's live URL too, optionally, for two more checks — everything we ask for is already public, never a credential beyond that key.",
  },
  {
    title: "First scan in 90 seconds",
    body: "Sixteen checks across four attack surfaces, the same ground an enterprise audit covers. You get a plain-English list of exactly what we found.",
  },
  {
    title: "Then we keep watching",
    body: "Every deploy triggers a re-scan, deep scans run on a schedule, and you only hear from us when something new appears. Silence means you're clean.",
  },
];

const STACK_SPEAKS = {
  builder: ["Lovable", "Bolt", "v0", "Cursor", "Replit"],
  database: ["Supabase"],
  host: ["Vercel", "Netlify"],
  source: ["GitHub"],
};

// Grouped from the real 16 checks lib/scanner.ts runs (docblock at the top
// of scanProject()) and the real finding titles lib/analyzer.ts produces —
// not from app/design/_shared/data.ts's mock CHECKS list, which this
// section used to (wrongly) copy. Every name here corresponds to an actual
// function in the scanner; nothing here is aspirational.
const SURFACES: { name: string; blurb: string; checks: string[] }[] = [
  {
    name: "Auth & access",
    blurb: "Who can sign in, hammer your endpoints, or reach admin routes they shouldn't.",
    checks: ["Auth admin endpoint exposure", "Login rate limiting", "REST API rate limiting"],
  },
  {
    name: "Data exposure",
    blurb: "Whether your database or storage answers questions it should refuse to answer.",
    checks: ["Row-level security", "Unauthenticated table access", "IDOR on user data", "Public storage buckets"],
  },
  {
    name: "Configuration",
    blurb: "Settings, dependencies, and headers that quietly decide how protected you are.",
    checks: ["Service-role key exposure", "Secrets & .env exposure", "HTTPS enforcement", "Bot-protection headers", "CORS wildcard policy", "Dependency slop-squatting"],
  },
  {
    name: "Injection & logic",
    blurb: "Whether crafted input or a sloppy endpoint can make your app do things you never wrote.",
    checks: ["Mass assignment", "SQL error / input validation", "Stack trace exposure"],
  },
];

const PRICING = {
  paid: {
    price: "$49",
    per: "/month",
    tagline: "The $50k audit, running all the time.",
    features: [
      "Full 16-check scan across four attack surfaces",
      "Step-by-step fixes for every finding, as prompts for Cursor, Lovable, Bolt, v0",
      "A live edge that blocks credential stuffing, scanners, and floods — fails open, never a real user",
      "Optional GitHub scan: committed secrets, vulnerable deps, with fix PRs you approve",
      "Re-scan on every deploy; deep scans on schedule, critical checks hourly",
      "Alerts only when something new appears — silence means you're clean",
    ],
  },
  trialNote: "First 7 days free. Cancel anytime before you're charged.",
  contrastNote:
    "A one-time scan answers “am I OK today?” The retainer answers “am I still OK?” — every hour, every deploy, and in full depth every 48 hours.",
};

const TRUST_LINE =
  "We only ever ask for your app's public key, plus an optional public URL — never a credential beyond that key, the same one your own frontend already exposes to every visitor. No repo access, no admin tokens, no exceptions.";

export default function LandingPage() {
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
              <a href="#method">The method</a>
              <a href="#defense">Live defense</a>
              <Link href="/owasp">OWASP Top 10</Link>
              <Link href="/incidents">Real incidents</Link>
              <a href="#pricing">Pricing</a>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>

          <header className="dxd-hero">
            <div>
              <p className="dxd-eyebrow">Security on retainer · for apps that earn</p>
              <h1 className="dxd-display">
                <ProximityText text="You built something worth protecting." />
                <br />
                <em>
                  <ShinyText>We carry the worry.</ShinyText>
                </em>
              </h1>
              <p className="dxd-lede">
                ShipLock runs the same class of checks a $50,000 enterprise audit opens with — continuously,
                against your live app — and stands guard at your login while it does. Built for
                founders who shipped with AI, found paying users, and would rather not bet the
                business on their own security guesswork.
              </p>
              <div className="dxd-hero-actions">
                <a href="#get-started" className="dxd-btn dxd-btn-paper">
                  Put us on retainer
                </a>
                <a href="#method" className="dxd-btn dxd-btn-ghost">
                  The method
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
        <section className="dxd-section" id="proof" style={{ paddingTop: 56 }} aria-label="Why founders put us on retainer">
          <div className="dxd-proof">
            <RevealList step={80}>
              <div>
                <div className="dxd-proof-num">$49</div>
                <div className="dxd-proof-label">The $50,000 enterprise audit — run continuously, for $49 a month.</div>
              </div>
              <div>
                <div className="dxd-proof-num">16</div>
                <div className="dxd-proof-label">Checks across four attack surfaces, re-run on every deploy.</div>
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
        </section>

        <section className="dxd-section" id="stakes">
          <Reveal>
            <p className="dxd-eyebrow">Why this matters</p>
            <h2 className="dxd-h2">One open table can undo two years of work.</h2>
            <p className="dxd-lede">
              Your app has paying customers now. That changes what a security mistake costs —
              it stops being embarrassing and starts being expensive. Three ways, specifically:
            </p>
          </Reveal>
          <div className="dxd-stakes">
            <RevealList step={90}>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">I · THE BREACH</span>
                <h3>Apps get broken through boring doors.</h3>
                <p>
                  Not Hollywood hacking — an unlocked database table, a sign-up flow that never
                  verifies emails, a key sitting in the client bundle. Attackers scan for these
                  automatically, at scale, every day.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">II · THE LEGAL WEIGHT</span>
                <h3>Customer data makes it a legal matter.</h3>
                <p>
                  The moment real people&apos;s data leaks, you owe things: breach notifications
                  to affected users, answers to privacy regulators, and potentially damages —
                  customers can and do sue over exposed personal data.
                </p>
              </SpotlightCard>
              <SpotlightCard className="dxd-stake">
                <span className="dxd-stake-num">III · THE TRUST</span>
                <h3>Revenue is trust with a renewal date.</h3>
                <p>
                  People pay you monthly because they assume you&apos;re keeping their data
                  safe. A breach converts your best customers into your loudest churn.
                </p>
              </SpotlightCard>
            </RevealList>
          </div>
          <Reveal>
            <p className="dxd-stake-close">
              You don&apos;t need to be scared of any of this. You need someone carrying it.
            </p>
          </Reveal>
          <Reveal>
            <p className="dxd-mono" style={{ marginTop: 28, fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)", borderLeft: "2px solid var(--d-bronze)", paddingLeft: 16 }}>
              This isn&apos;t hypothetical. CVE-2025-48757: 170+ live apps built with an AI
              builder were found serving names, emails, and financial data to anyone who asked —
              one missing database rule, rated CVSS 9.3.{" "}
              <Link href="/incidents" style={{ color: "var(--d-ink)" }}>
                We wrote up what actually happened →
              </Link>
            </p>
          </Reveal>
        </section>

        <section className="dxd-section" id="method">
          <p className="dxd-eyebrow">The method</p>
          <h2 className="dxd-h2">Three steps. Then the weight is ours.</h2>
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
              The audit runs against your live app — not your source, not your builder — so it
              works the moment you paste a key, whoever wrote the code. Four slots; every
              provider spoken.
            </p>
          </Reveal>
          <Reveal>
            <div className="dxd-speak" role="table" aria-label="Supported stack, by slot">
              {(
                [
                  { slot: "Builder", names: STACK_SPEAKS.builder, scope: "detected from the app itself — nothing to connect" },
                  { slot: "Database", names: STACK_SPEAKS.database, scope: "the public key your frontend already ships — never more" },
                  { slot: "Host", names: STACK_SPEAKS.host, scope: "coming soon · optional, read-only, selected projects" },
                  { slot: "Source", names: STACK_SPEAKS.source, scope: "optional · read-only — committed secrets, vulnerable deps, fix PRs you approve" },
                ] as const
              ).map((r) => (
                <div className="dxd-speak-row" role="row" key={r.slot}>
                  <span className="dxd-speak-cat" role="cell">{r.slot}</span>
                  <span className="dxd-speak-names" role="cell">
                    {r.names.map((n, i) => (
                      <span key={n}>
                        {i > 0 && <i aria-hidden="true"> · </i>}
                        {n}
                      </span>
                    ))}
                  </span>
                  <span className="dxd-speak-scope dxd-mono" role="cell">{r.scope}</span>
                </div>
              ))}
            </div>
          </Reveal>
        </section>

        <section className="dxd-section" id="what-we-check">
          <p className="dxd-eyebrow">Scope of engagement</p>
          <h2 className="dxd-h2">Sixteen checks, named precisely.</h2>
          <p className="dxd-lede" style={{ marginBottom: 8 }}>
            You know your stack. Here is exactly what we hold against it — no euphemisms.
          </p>
          <div className="dxd-surfaces">
            {SURFACES.map((s) => (
              <SpotlightCard className="dxd-surface" key={s.name}>
                <h3>{s.name}</h3>
                <p>{s.blurb}</p>
                <ul>
                  {s.checks.map((c) => (
                    <li key={c}>
                      <span>{c.toLowerCase()}</span>
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
                {TRUST_LINE} You&apos;re technical enough to audit us — so we make it possible,
                and unnecessary.
              </p>
            </div>
            <Seal state="intact" size={148} />
          </div>
        </section>

        <section className="dxd-section" id="fixes">
          <Reveal>
            <p className="dxd-eyebrow">The handoff</p>
            <h2 className="dxd-h2">Findings arrive as fixes — one button, fully reviewable.</h2>
            <p className="dxd-lede">
              Every finding comes with an exact fix and a button to apply it. Database and
              access-control changes open a migration pull request you review, edit, and merge —
              your own deploy applies it. We never write to your database directly. Nothing about
              a fix is silent; each one is a diff you approve.
            </p>
          </Reveal>
          <Reveal>
            <div className="dxd-surface" style={{ maxWidth: 640, margin: "28px auto 0" }}>
              <p className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", textTransform: "uppercase", letterSpacing: "0.1em", margin: "0 0 12px" }}>
                Example fix — anonymized · one reviewable PR per finding
              </p>
              <p className="dxd-mono" style={{ fontSize: 12.5, lineHeight: 1.7, margin: 0, color: "var(--d-ink)", background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8, padding: "14px 16px" }}>
                supabase/migrations/…_shiplock_enable_rls_invoices.sql<br />
                ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;<br />
                CREATE POLICY owner_only ON invoices<br />
                &nbsp;&nbsp;USING (auth.uid() = user_id);
              </p>
              <p style={{ marginTop: 14, fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted)" }}>
                Opened as a pull request you read, edit, and merge — never applied to your
                production database by us. Auth, RLS, and data changes stay in your hands, by
                design.
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

        <section className="dxd-section" id="watch">
          <Reveal>
            <p className="dxd-eyebrow">The watch, in practice</p>
            <h2 className="dxd-h2">What we monitor — and exactly how.</h2>
            <p className="dxd-lede">
              A scan is a photograph, and your app doesn&apos;t hold still. One prompt to your
              coding agent tomorrow can quietly undo today&apos;s fix — which is why a
              point-in-time report, however deep, expires on your next deploy. So we re-check,
              on every deploy and on a schedule, and only speak up when something actually
              changed.
            </p>
          </Reveal>
          <div className="dxd-watchrows">
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Every deploy, re-audited</h3>
                <p>
                  Add ShipLock&apos;s webhook URL to your Vercel project once. Every production
                  deploy triggers an immediate re-scan.
                </p>
              </div>
            </Reveal>
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Deep audits on schedule, critical checks hourly</h3>
                <p>
                  A full 16-check pass re-runs every 48 hours; a lightweight critical-checks
                  pass runs every hour, watching the fastest-moving risks.
                </p>
              </div>
            </Reveal>
            <Reveal>
              <div className="dxd-watchrow">
                <h3>Alerts that respect you</h3>
                <p>
                  You hear from us when something <b>new</b> appears — once, with the brief
                  attached. No re-alerts on things you already know. Silence is a statement:
                  everything held.
                </p>
              </div>
            </Reveal>
          </div>
        </section>

        <section className="dxd-section" id="defense">
          <Reveal>
            <p className="dxd-eyebrow">The front door · live</p>
            <h2 className="dxd-h2">Between scans, we stand at your door.</h2>
            <p className="dxd-lede">
              Scanning finds the holes. But your login page is being knocked on right now —
              credential-stuffing bots, vulnerability scanners, brute-force floods, all
              automated, all indifferent to how careful you were. So we don&apos;t just report
              them. We watch the attack take shape, and the moment it&apos;s unmistakable, we
              shut that source out.
            </p>
          </Reveal>
          <Reveal delay={80}>
            <div style={{ marginTop: 28 }}>
              <TrafficDefense />
            </div>
          </Reveal>
          <div className="dxd-watchrows" style={{ marginTop: 32 }}>
            <RevealList step={90}>
              <div className="dxd-watchrow">
                <h3>One small file — and it fails open, always</h3>
                <p>
                  We generate a snippet for your app (Next.js, Hono, Cloudflare Workers,
                  Express). It watches only your auth and API routes. If ShipLock is ever
                  unreachable, it does nothing at all and your app serves normally — we can never
                  be the reason you go down. No DNS changes, no proxy in front of you.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>We&apos;re sure before we ever turn traffic away</h3>
                <p>
                  We don&apos;t block on a hunch. The first unusual requests get through — and
                  get mirrored to us. Only once the pattern is unmistakable (a burst of logins, a
                  scanner walking <code>.env</code> and <code>wp-admin</code>, a flood) does that
                  source get blocked; its next requests get a 429. Anything ambiguous we flag,
                  never block — so a real customer of yours never hits a wall they didn&apos;t
                  deserve.
                </p>
              </div>
              <div className="dxd-watchrow">
                <h3>A stolen session, caught in the act</h3>
                <p>
                  One valid login suddenly used from many places at once is the signature of a
                  hijacked session — something no configuration scan can ever see. We watch for
                  it and tell you, without ever touching the token itself; we only see a salted
                  hash, never the session.
                </p>
              </div>
            </RevealList>
          </div>
        </section>

        <section className="dxd-section" id="honest">
          <Reveal>
            <p className="dxd-eyebrow">What we won&apos;t promise</p>
            <h2 className="dxd-h2">No one can make your app unhackable. We&apos;ll never pretend otherwise.</h2>
            <p className="dxd-lede">
              Every tool that promises &ldquo;100% protected&rdquo; is selling you something, and
              some part of you already knows it. Software has bugs; people make mistakes;
              determined attackers are patient. What&apos;s actually true is quieter and more
              useful: almost every app that gets breached is breached through a known, ordinary,
              closeable hole. We close those, we watch them stay closed, and we turn away the
              automated attacks hitting your door — which moves you from the app that gets
              breached to the one that isn&apos;t worth the effort.
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
                marginTop: 40,
                fontSize: 12.5,
                lineHeight: 1.75,
                color: "var(--d-ink)",
                borderLeft: "2px solid var(--d-bronze)",
                paddingLeft: 16,
                maxWidth: 720,
              }}
            >
              And we tell you what we <em>can&apos;t</em> see. Your business logic, the auth
              checks inside your own code — no scanner reads those. Rather than quietly leaving
              them off the report, we hand you the exact prompts to audit them yourself. The
              honesty is the product.
            </p>
          </Reveal>
        </section>

        <section className="dxd-section" id="pricing">
          <p className="dxd-eyebrow">Terms</p>
          <h2 className="dxd-h2">One engagement. One number.</h2>
          <div className="dxd-pricing">
            <SpotlightCard className="dxd-price-card dxd-featured">
              <p className="dxd-price-name">The retainer · monitor</p>
              <p className="dxd-price dxd-serif">
                {PRICING.paid.price}
                <span>{PRICING.paid.per}</span>
              </p>
              <p className="dxd-price-tag">{PRICING.paid.tagline}</p>
              <ul>
                {PRICING.paid.features.map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
              <a href="#get-started" className="dxd-btn">
                Put us on retainer
              </a>
            </SpotlightCard>
          </div>
          <p className="dxd-rescan-note">{PRICING.contrastNote}</p>
          <p className="dxd-rescan-note">{PRICING.trialNote}</p>
        </section>

        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">Get started</p>
            <h2 className="dxd-h2">Connect your project. We carry the rest.</h2>
            <p className="dxd-lede">
              Sign in, put us on retainer — 7 days free before the first charge — then paste
              your Supabase URL and anon key (and, optionally, your app&apos;s live URL for two
              more checks). The first audit — every finding, and the fix for each — runs immediately.
            </p>
          </Reveal>
          <Reveal delay={100}>
            <div style={{ marginTop: 28, display: "flex", justifyContent: "center" }}>
              <OAuthButtons />
            </div>
          </Reveal>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span> On retainer since
            today.
          </span>
          <span>
            <Link href="/owasp">OWASP Top 10</Link> · <Link href="/incidents">Real incidents</Link>{" "}
            · <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link> ·{" "}
            <Link href="/dashboard-preview">Product preview →</Link> · support@shiplock.dev
          </span>
        </footer>
      </div>
    </main>
  );
}
