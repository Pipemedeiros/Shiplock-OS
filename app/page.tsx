import Link from "next/link";
import { FloatingLines } from "@/components/marketing/floating-lines";
import { LogoLoop } from "@/components/marketing/logo-loop";
import { ScrollReveal } from "@/components/marketing/scroll-reveal";
import { OAuthButtons } from "@/components/marketing/oauth-buttons";
import { LegalAccordion } from "@/components/marketing/legal-accordion";

// This page has no dynamic data, so Next would otherwise statically
// prerender it at build time — before middleware.ts ever runs, and before
// any request-scoped CSP nonce exists. The cached static HTML's scripts
// then carry no nonce (or a stale one), while middleware sets a brand-new
// nonce on every live request; the browser blocks every script whose nonce
// doesn't match, including Next's own hydration/RSC-streaming payloads —
// silently blanking the whole page below whatever painted synchronously.
// Forcing dynamic rendering keeps the HTML (and its script nonces) in sync
// with the header middleware sets for that same request.
export const dynamic = "force-dynamic";

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "text-sev-critical bg-sev-critical/10 border-sev-critical/25",
  High: "text-sev-high bg-sev-high/10 border-sev-high/25",
  Medium: "text-sev-medium bg-sev-medium/10 border-sev-medium/25",
  Pass: "text-sev-pass bg-sev-pass/10 border-sev-pass/25",
};

const EXAMPLE_FINDINGS = [
  { severity: "Critical", text: "storage bucket 'user-uploads' is publicly readable" },
  { severity: "High", text: "RLS disabled on table 'invoices'" },
  { severity: "Medium", text: "no rate limit on /auth/v1/token" },
  { severity: "Pass", text: "service role key not exposed to client" },
];

function SeverityTag({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wide uppercase ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

function ExampleAuditPanel() {
  return (
    <div className="w-full max-w-md rounded-2xl border border-border bg-card p-6 shadow-[0_8px_30px_-12px_rgba(15,23,42,0.18)]">
      <div className="mb-4 flex items-center justify-between">
        <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">
          Example audit — anonymized
        </p>
        <span className="rounded bg-secondary px-2 py-0.5 font-mono text-[11px] text-muted-foreground">
          scan #4471
        </span>
      </div>

      <div className="mb-5 flex items-baseline gap-3">
        <span className="font-display text-5xl font-bold text-foreground">C+</span>
        <span className="text-sm text-muted-foreground">4 issues found · 1 critical</span>
      </div>

      <div className="space-y-2 font-mono text-[13px]">
        {EXAMPLE_FINDINGS.map((f) => (
          <div
            key={f.text}
            className="flex items-center gap-2.5 rounded-lg border border-border bg-secondary/50 px-3 py-2"
          >
            <SeverityTag severity={f.severity} />
            <span className="truncate text-foreground/80">{f.text}</span>
          </div>
        ))}
      </div>

      <p className="mt-4 text-[11px] leading-relaxed text-muted-foreground">
        Free scans show findings and consequences. Fixes and ready-to-paste code prompts unlock on Pro.
      </p>
    </div>
  );
}

const WHAT_WE_CHECK = [
  {
    source: "Database connection",
    status: "live" as const,
    description:
      "You give us your Supabase URL and anon key — the same credentials your own frontend uses. We run all 15 checks: row-level security gaps, exposed service role keys, missing rate limits, mass-assignment risk, public storage buckets, weak auth configuration, and more. Read-only, zero rows read from your tables.",
  },
  {
    source: "URL-only baseline",
    status: "live" as const,
    description:
      "No credentials at all — just your project URL. We run the subset of checks that don't require an anon key (HTTPS enforcement, exposed secrets, stack-trace leakage) so you get a baseline read before connecting anything.",
  },
  {
    source: "Continuous re-verification",
    status: "live" as const,
    description:
      "Once connected, Pro accounts get re-scanned automatically: a lightweight 4-check pass hourly (RLS, key exposure, public buckets, service-role leakage), a full 15-check pass every 48 hours, and an immediate re-scan when your Vercel project deploys to production.",
  },
  {
    source: "GitHub source scanning",
    status: "soon" as const,
    description:
      "Direct repo access to scan for hardcoded secrets, dependency CVEs, and insecure patterns before they ship — not just what's reachable from the outside.",
  },
  {
    source: "Vercel config audit",
    status: "soon" as const,
    description:
      "Automatic connection to your Vercel project to check environment variable hygiene and deployment configuration, without a manual webhook paste.",
  },
];

const FAQS = [
  {
    q: "Do you need my database password?",
    a: "No. We use the same anon key your app's frontend already uses — the credentials that are, by definition, exposed to anyone who opens your browser's dev tools. We never ask for your Supabase service role key or database password, and if one is ever submitted by mistake, we discard it immediately and flag it as a critical finding.",
  },
  {
    q: "What's the difference between this and a one-time scan?",
    a: "A one-time scan tells you your security posture on the day you ran it. Every deploy after that is unverified. ShipLock re-checks after every production deploy and on a fixed schedule, so a regression — an RLS policy someone disabled while debugging, a bucket made public for a demo and never reverted — gets caught within hours, not discovered by an attacker months later.",
  },
  {
    q: "Why is this so much cheaper than a real security audit?",
    a: "A traditional application security audit is manual, expert time — that's why it costs $50,000+ and takes weeks. ShipLock automates the checks that manual auditors run first: authorization gaps, exposed credentials, missing rate limits, misconfigured storage. It's not a replacement for deep manual penetration testing on funded, high-stakes systems — it's the continuous baseline that most small SaaS products never get at all.",
  },
  {
    q: "What happens if you find something critical?",
    a: "Free scans show you the finding, its severity, and what it means in plain language — for example, what an attacker could actually do with a publicly readable storage bucket. Pro unlocks the fix itself and a ready-to-paste prompt for your AI coding tool, so you can hand it directly to Lovable, Bolt, Cursor, or v0 and ship the patch.",
  },
  {
    q: "Can I use this if I don't know what RLS is?",
    a: "Yes — that's who this is built for. Every finding explains the real-world consequence in plain language before it explains the technical mechanism. You don't need to know what Row Level Security is to understand \"anyone on the internet can read every user's private messages.\"",
  },
];

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-background text-foreground">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/85 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2">
            <svg viewBox="0 0 32 32" className="size-6 shrink-0" aria-hidden>
              <path fill="var(--foreground)" d="M16 2 L28 7 V16 C28 24 22 29 16 30 C10 29 4 24 4 16 V7 Z" />
              <path
                fill="var(--accent-indigo)"
                d="M13 15 C13 12 14.5 10 16 10 C17.5 10 19 12 19 15 L19 16 L20 16 C20.6 16 21 16.4 21 17 L21 23 C21 23.6 20.6 24 20 24 L12 24 C11.4 24 11 23.6 11 23 L11 17 C11 16.4 11.4 16 12 16 L13 16 Z"
              />
            </svg>
            <span className="text-[15px] font-semibold tracking-tight text-foreground">ShipLock</span>
          </Link>
          <nav className="hidden items-center gap-8 md:flex">
            <a href="#methodology" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              How It Works
            </a>
            <a href="#what-we-check" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              What We Check
            </a>
            <a href="#pricing" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Pricing
            </a>
          </nav>
          <a
            href="#get-started"
            className="rounded-lg bg-accent-indigo px-4 py-2 text-sm font-medium text-white shadow-sm transition-opacity hover:opacity-90"
          >
            Get Started
          </a>
        </div>
      </header>

      {/* Hero */}
      <section className="relative overflow-hidden px-6 pt-20 pb-24">
        <FloatingLines />
        <div className="mx-auto grid max-w-6xl items-center gap-16 lg:grid-cols-[1.1fr_0.9fr]">
          <div>
            <p className="mb-5 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              Continuous application security
            </p>
            <h1 className="font-display text-5xl leading-[1.08] font-bold text-foreground sm:text-6xl">
              Enterprise-grade security audits,
              <br />
              running every day instead of once a year.
            </h1>
            <p className="mt-7 max-w-xl text-lg leading-relaxed text-muted-foreground">
              A real application security audit costs $50,000 and takes six to eight weeks —
              once a year, if a company can afford it at all. ShipLock runs that same depth of
              checking continuously, against apps built on Lovable, Bolt, v0, and Cursor, for $49
              a month.
            </p>
            <div className="mt-9 flex flex-wrap items-center gap-4">
              <a
                href="#get-started"
                className="rounded-lg bg-accent-indigo px-6 py-3.5 text-[15px] font-medium text-white shadow-sm transition-opacity hover:opacity-90"
              >
                Get Started
              </a>
              <a
                href="#methodology"
                className="text-[15px] font-medium text-foreground/80 underline decoration-border underline-offset-4 transition-colors hover:text-foreground"
              >
                See how it works
              </a>
            </div>
          </div>

          <div className="flex justify-center lg:justify-end">
            <ExampleAuditPanel />
          </div>
        </div>
      </section>

      {/* Methodology */}
      <section id="methodology" className="border-t border-border px-6 py-24">
        <div className="mx-auto max-w-3xl">
          <ScrollReveal>
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              Why continuous
            </p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
              A security grade is only true on the day you earned it.
            </h2>
          </ScrollReveal>

          <ScrollReveal delayMs={80} className="mt-8 space-y-5 text-[17px] leading-relaxed text-muted-foreground">
            <p>
              Most security tools — and most manual audits — check your app once and hand you a
              report. That report describes your app as it existed on one specific day. The next
              day you ship a change, ask an AI coding assistant to &quot;quickly fix&quot;
              something, or debug a permissions issue by turning off a policy and forgetting to
              turn it back on — and the report is already wrong.
            </p>
            <p>
              ShipLock treats security as a state that needs to be re-verified, not a grade you earn
              once. After the initial onboarding attack finds your real starting point, we
              re-check automatically: a lightweight pass every hour, a full deep scan every 48
              hours, and an immediate re-scan the moment your app redeploys to production. You
              only hear from us when something changed for the worse — silence means everything is
              still clean.
            </p>
            <p>
              This is the same principle enterprise security teams operate on with expensive
              tooling and dedicated staff. ShipLock automates the parts of that process that don&apos;t
              require a human — the parts most $1k–5k MRR products never get access to at all.
            </p>
          </ScrollReveal>
        </div>
      </section>

      {/* What we check */}
      <section id="what-we-check" className="border-t border-border bg-secondary/30 px-6 py-24">
        <div className="mx-auto max-w-5xl">
          <ScrollReveal className="mx-auto max-w-2xl text-center">
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              What we check
            </p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
              Organized by where we&apos;re connected.
            </h2>
            <p className="mt-4 text-lg leading-relaxed text-muted-foreground">
              We label every source honestly. Three are live today. Two are on the roadmap and not
              yet built — we say so plainly rather than implying they already work.
            </p>
          </ScrollReveal>

          <ScrollReveal delayMs={80} className="mt-12">
            <LogoLoop />
          </ScrollReveal>

          <div className="mt-8 grid gap-4 sm:grid-cols-2">
            {WHAT_WE_CHECK.map((item, i) => (
              <ScrollReveal key={item.source} delayMs={i * 60}>
                <div className="h-full rounded-xl border border-border bg-card p-6 shadow-sm">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h3 className="text-base font-semibold text-foreground">{item.source}</h3>
                    {item.status === "live" ? (
                      <span className="shrink-0 rounded-full border border-sev-pass/30 bg-sev-pass/10 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide text-sev-pass uppercase">
                        Live today
                      </span>
                    ) : (
                      <span className="shrink-0 rounded-full border border-border bg-secondary px-2.5 py-0.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
                        Coming soon
                      </span>
                    )}
                  </div>
                  <p className="text-sm leading-relaxed text-muted-foreground">{item.description}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* Get Started */}
      <section id="get-started" className="border-t border-border px-6 py-24">
        <div className="mx-auto flex max-w-3xl flex-col items-center text-center">
          <ScrollReveal>
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              Get started
            </p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
              Connect your project. Get your first audit free.
            </h2>
            <p className="mt-4 max-w-lg text-lg leading-relaxed text-muted-foreground">
              Sign in, then paste your Supabase URL and anon key from your dashboard. Your first
              onboarding attack — grade, findings, and the fix for your most critical issue — is
              free.
            </p>
          </ScrollReveal>

          <ScrollReveal delayMs={100} className="mt-9 flex justify-center">
            <OAuthButtons />
          </ScrollReveal>
        </div>
      </section>

      {/* Monitoring */}
      <section className="border-t border-border bg-secondary/30 px-6 py-24">
        <div className="mx-auto max-w-3xl">
          <ScrollReveal>
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              Monitoring
            </p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
              How re-checking actually works.
            </h2>
          </ScrollReveal>

          <ScrollReveal delayMs={80} className="mt-8 grid gap-4 sm:grid-cols-3">
            {[
              {
                title: "On every deploy",
                body: "Add ShipLock's webhook URL to your Vercel project once. Every production deploy triggers an immediate re-scan.",
              },
              {
                title: "Every hour",
                body: "A lightweight 4-check pass watches for the fastest-moving risks: RLS being disabled, keys leaking, buckets going public.",
              },
              {
                title: "Every 48 hours",
                body: "A full 15-check pass re-runs the complete onboarding audit, catching anything the lightweight pass doesn't cover.",
              },
            ].map((m) => (
              <div key={m.title} className="rounded-xl border border-border bg-card p-5">
                <h3 className="mb-2 text-sm font-semibold text-foreground">{m.title}</h3>
                <p className="text-sm leading-relaxed text-muted-foreground">{m.body}</p>
              </div>
            ))}
          </ScrollReveal>

          <ScrollReveal delayMs={140} className="mt-6 text-sm leading-relaxed text-muted-foreground">
            Every pass is diffed against the last one. You&apos;re only alerted on findings that are
            new — a finding that hasn&apos;t changed since your last check stays silent. No daily
            digest of things you already know about.
          </ScrollReveal>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="border-t border-border px-6 py-24">
        <div className="mx-auto max-w-4xl">
          <ScrollReveal className="text-center">
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
              Pricing
            </p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
              One audit free. Continuous coverage for $49/month.
            </h2>
          </ScrollReveal>

          <div className="mt-12 grid gap-6 sm:grid-cols-2">
            <ScrollReveal delayMs={60}>
              <div className="h-full rounded-2xl border border-border bg-card p-8">
                <h3 className="text-lg font-semibold text-foreground">Free</h3>
                <p className="mt-1 text-sm text-muted-foreground">One onboarding attack</p>
                <p className="mt-6 font-display text-4xl font-bold text-foreground">$0</p>
                <ul className="mt-6 space-y-3 text-sm text-muted-foreground">
                  <li>— Full 15-check attack against your live project</li>
                  <li>— Grade (A–F) and issue count</li>
                  <li>— Every finding&apos;s title, severity, and real-world consequence</li>
                  <li>— The fix for your single most critical issue</li>
                </ul>
              </div>
            </ScrollReveal>

            <ScrollReveal delayMs={120}>
              <div className="h-full rounded-2xl border-2 border-accent-indigo bg-card p-8 shadow-[0_8px_30px_-12px_rgba(79,70,229,0.25)]">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-foreground">Pro</h3>
                  <span className="rounded-full bg-accent-indigo/10 px-2.5 py-0.5 text-[11px] font-semibold text-accent-indigo uppercase">
                    Most coverage
                  </span>
                </div>
                <p className="mt-1 text-sm text-muted-foreground">Continuous monitoring</p>
                <p className="mt-6 font-display text-4xl font-bold text-foreground">
                  $49<span className="text-lg font-medium text-muted-foreground">/mo</span>
                </p>
                <ul className="mt-6 space-y-3 text-sm text-muted-foreground">
                  <li>— Everything in Free</li>
                  <li>— All fixes, with ready-to-paste code prompts for your AI coding tool</li>
                  <li>— Hourly lightweight re-checks, full 48-hour deep scans</li>
                  <li>— Deploy-triggered re-scan on every Vercel production push</li>
                  <li>— New-finding alerts only — no noise on unchanged issues</li>
                </ul>
              </div>
            </ScrollReveal>
          </div>

          <ScrollReveal delayMs={180} className="mt-6 text-center text-sm text-muted-foreground">
            Need an audit outside your weekly cycle? A one-time re-scan is $2.
          </ScrollReveal>
        </div>
      </section>

      {/* FAQ */}
      <section className="border-t border-border bg-secondary/30 px-6 py-24">
        <div className="mx-auto max-w-2xl">
          <ScrollReveal className="text-center">
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">FAQ</p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">Questions worth asking.</h2>
          </ScrollReveal>

          <div className="mt-10 flex flex-col gap-3">
            {FAQS.map((f, i) => (
              <ScrollReveal key={f.q} delayMs={i * 40}>
                <details className="group rounded-xl border border-border bg-card open:shadow-sm">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 text-sm font-medium text-foreground">
                    {f.q}
                    <span className="shrink-0 text-muted-foreground transition-transform group-open:rotate-45">+</span>
                  </summary>
                  <div className="border-t border-border px-5 py-5">
                    <p className="text-sm leading-relaxed text-muted-foreground">{f.a}</p>
                  </div>
                </details>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* Legal */}
      <section className="border-t border-border px-6 py-24">
        <div className="mx-auto max-w-2xl">
          <ScrollReveal className="text-center">
            <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">Legal</p>
            <h2 className="font-display text-3xl font-bold text-foreground sm:text-4xl">The fine print.</h2>
          </ScrollReveal>
          <div className="mt-10">
            <LegalAccordion />
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border px-6 py-10">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 sm:flex-row">
          <span className="text-sm text-muted-foreground">© 2026 ShipLock. Built for founders who ship fast.</span>
          <span className="text-sm text-muted-foreground">support@shiplock.dev</span>
        </div>
      </footer>
    </main>
  );
}
