import Link from "next/link";
import { OAuthButtons } from "@/components/marketing/oauth-buttons";
import { ProximityText, Reveal, RevealList, ShinyText, SpotlightCard } from "@/components/d/bits";
import { Seal } from "@/components/d/Seal";
import { LockMark } from "@/components/d/Brand";

// Real landing page, Design D visuals. Same reason as before this reskin:
// no dynamic data here, so Next would otherwise statically prerender at
// build time — before middleware.ts's per-request CSP nonce exists —
// silently blocking every client script. Force dynamic rendering to keep
// this page's script nonces in sync with the header middleware sets for
// each request.
export const dynamic = "force-dynamic";

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
        <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", background: "var(--d-porcelain)", padding: "2px 7px", borderRadius: 4 }}>
          scan #4471
        </span>
      </div>

      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 20 }}>
        <span className="dxd-serif" style={{ fontSize: 44, fontWeight: 700 }}>C+</span>
        <span style={{ fontSize: 14, color: "var(--d-muted)" }}>4 issues found · 1 critical</span>
      </div>

      <div className="dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 8, fontSize: 12.5 }}>
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
        A sample of what lands in your dashboard on retainer — grade, every finding, and a
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
    body: "Sixteen checks across four attack surfaces, the same ground an enterprise audit covers. You get a grade and a plain-English list of what we found.",
  },
  {
    title: "Then we keep watching",
    body: "Every deploy triggers a re-scan, deep scans run on a schedule, and you only hear from us when something new appears. Silence means you're clean.",
  },
];

const STACK_SPEAKS = {
  builder: ["Lovable", "Bolt", "v0", "Cursor", "Replit"],
  database: ["Supabase", "Firebase"],
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
      "Full 16-check scan, grade A through F",
      "Step-by-step fixes for every finding",
      "Copy-paste prompts for whatever you build in — Cursor, Lovable, Bolt, v0",
      "An AI-agent brief on your dashboard, ready to hand your coding tool",
      "Re-scan on every deploy",
      "Scheduled deep scans, critical checks hourly",
      "Alerts only when something new appears",
    ],
  },
  trialNote: "First 7 days free. Cancel anytime before you're charged.",
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
                against your live app. Built for founders who shipped with AI, found paying
                users, and would rather not bet the business on their own security guesswork.
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
                  { slot: "Host", names: STACK_SPEAKS.host, scope: "optional · read-only, selected projects" },
                  { slot: "Source", names: STACK_SPEAKS.source, scope: "optional · contents: read-only — powers fix PRs" },
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

        <section className="dxd-section" id="watch">
          <Reveal>
            <p className="dxd-eyebrow">The watch, in practice</p>
            <h2 className="dxd-h2">What we monitor — and exactly how.</h2>
            <p className="dxd-lede">
              We label every source honestly. Some of this is live today; the rest is on the
              roadmap and we say so plainly rather than implying it already works.
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
                <div>
                  <h3>A protective front door</h3>
                  <span className="dxd-soon">joining the retainer</span>
                </div>
                <p>
                  One DNS record points your domain at an edge we operate. At that front door,
                  bursts get rate-limited and credential-stuffing bots are turned away before
                  they ever reach your sign-in page.
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
          <p className="dxd-rescan-note">{PRICING.trialNote}</p>
        </section>

        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">Get started</p>
            <h2 className="dxd-h2">Connect your project. We carry the rest.</h2>
            <p className="dxd-lede">
              Sign in, put us on retainer — 7 days free before the first charge — then paste
              your Supabase URL and anon key (and, optionally, your app&apos;s live URL for two
              more checks). The first audit, grade and every finding, runs immediately.
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
