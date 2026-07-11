import Link from "next/link";
import { Reveal, SpotlightCard } from "@/components/d/bits";
import { LockMark } from "@/components/d/Brand";

// Real incidents, not hypotheticals — every claim here is sourced (NVD,
// CISA, vendor security blogs, or the CVE record itself) and linked.
// Deliberately honest about scope: CVE-2025-29927 is included with the
// caveat that it doesn't affect Vercel-hosted apps and isn't something our
// anon-key-based external scan can detect at all — awareness, not a false
// detection claim.
export const dynamic = "force-dynamic";

export default function IncidentsPage() {
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
              <Link href="/owasp">OWASP Top 10</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>

          <header className="dxd-hero" style={{ gridTemplateColumns: "1fr" }}>
            <div>
              <p className="dxd-eyebrow">This already happened</p>
              <h1 className="dxd-display" style={{ fontSize: "clamp(32px,5vw,52px)" }}>
                Real incidents, not hypotheticals.
              </h1>
              <p className="dxd-lede">
                Every claim on this page is sourced and linked — NVD, CISA, or the vendor&apos;s
                own security writeup. No invented statistics.
              </p>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        <section className="dxd-section">
          <Reveal>
            <p className="dxd-eyebrow">The anchor case</p>
            <h2 className="dxd-h2">CVE-2025-48757 — 170+ real apps, exactly this pattern.</h2>
          </Reveal>
          <Reveal>
            <div style={{ maxWidth: 720 }}>
            <SpotlightCard className="dxd-surface">
              <p style={{ fontSize: 15, lineHeight: 1.7 }}>
                In May 2025, security researcher Matt Palmer disclosed that 303 endpoints across
                170 real apps built with Lovable — 10.3% of the projects he analyzed — could be
                read or written by anyone, unauthenticated, because Row Level Security was left
                off. NVD rated it CVSS 9.3, critical, CWE-863 (incorrect authorization). NVD&apos;s
                own description: &ldquo;An insufficient database Row-Level Security policy in
                Lovable&hellip; allows remote unauthenticated attackers to read or write to
                arbitrary database tables of generated sites.&rdquo;
              </p>
              <p style={{ fontSize: 15, lineHeight: 1.7, marginTop: 12 }}>
                One detail worth sitting with: the vendor&apos;s own response disputed that this
                was a Lovable bug at all — their position was that customers are responsible for
                protecting their own application data. Whether or not you think that&apos;s fair,
                it&apos;s the reality every builder on every AI coding tool ships into. RLS is off
                by default on new Supabase tables, and nobody except you is going to turn it on.
              </p>
              <p className="dxd-keynote" style={{ marginTop: 12 }}>
                This is exactly check 1 of our 16 — RLS per table — on every scan, every hour,
                every 48 hours, for as long as you&apos;re on retainer.
              </p>
              <p style={{ marginTop: 16, fontSize: 12.5 }}>
                <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-48757" target="_blank" rel="noopener noreferrer">NVD: CVE-2025-48757 →</a>
                {" · "}
                <a href="https://supabase.com/blog/supabase-security-2025-retro" target="_blank" rel="noopener noreferrer">Supabase&apos;s own 2025 security retro →</a>
              </p>
            </SpotlightCard>
            </div>
          </Reveal>
        </section>

        <section className="dxd-section">
          <Reveal>
            <p className="dxd-eyebrow">Supply chain</p>
            <h2 className="dxd-h2">Shai-Hulud — a self-replicating npm worm.</h2>
          </Reveal>
          <Reveal>
            <div style={{ maxWidth: 720 }}>
            <SpotlightCard className="dxd-surface">
              <p style={{ fontSize: 15, lineHeight: 1.7 }}>
                Starting September 2025, a worm nicknamed Shai-Hulud spread through the npm
                registry: attackers compromised a maintainer&apos;s account via phishing, published
                malicious versions of their packages, then used the stolen credentials to infect
                every other package that maintainer owned — self-replicating without further
                human involvement. CISA issued an alert. A second, more aggressive wave
                (&ldquo;Shai-Hulud 2.0&rdquo;) hit in November 2025, compromising hundreds more
                packages and, in some cases, attempting to destroy the infected machine&apos;s home
                directory.
              </p>
              <p className="dxd-keynote" style={{ marginTop: 12 }}>
                Partial coverage: our dependency slop-squatting check flags packages that look
                invented or suspiciously new in your package.json — a related but narrower
                problem than a worm compromising an already-trusted package after installation.
                Full dependency-vulnerability scanning needs source access, which is a roadmap
                item, not live today.
              </p>
              <p style={{ marginTop: 16, fontSize: 12.5 }}>
                <a href="https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem" target="_blank" rel="noopener noreferrer">CISA alert →</a>
                {" · "}
                <a href="https://unit42.paloaltonetworks.com/npm-supply-chain-attack/" target="_blank" rel="noopener noreferrer">Palo Alto Unit 42 writeup →</a>
              </p>
            </SpotlightCard>
            </div>
          </Reveal>
        </section>

        <section className="dxd-section">
          <Reveal>
            <p className="dxd-eyebrow">Awareness, not a claim of coverage</p>
            <h2 className="dxd-h2">CVE-2025-29927 — Next.js middleware bypass.</h2>
          </Reveal>
          <Reveal>
            <div style={{ maxWidth: 720 }}>
            <SpotlightCard className="dxd-surface">
              <p style={{ fontSize: 15, lineHeight: 1.7 }}>
                A CVSS 9.1 vulnerability disclosed in March 2025: a crafted request header
                (<code>x-middleware-subrequest</code>) could trick vulnerable Next.js versions
                into skipping middleware entirely — including whatever auth checks your
                middleware was supposed to enforce.
              </p>
              <p style={{ fontSize: 15, lineHeight: 1.7, marginTop: 12 }}>
                Included here for awareness, with two honest caveats. First: Vercel confirmed
                apps hosted on Vercel were never affected by this one — the platform&apos;s own
                request handling doesn&apos;t expose the vulnerable path. Second, and more
                important: this is a hosting/source-layer issue, not something our anon-key,
                external, database-focused scan can detect at all. Catching this class of bug
                would need source access — the not-yet-built GitHub App integration on our
                roadmap, not a claim we make today.
              </p>
              <p style={{ marginTop: 16, fontSize: 12.5 }}>
                <a href="https://nvd.nist.gov/vuln/detail/CVE-2025-29927" target="_blank" rel="noopener noreferrer">NVD: CVE-2025-29927 →</a>
                {" · "}
                <a href="https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/" target="_blank" rel="noopener noreferrer">Datadog Security Labs writeup →</a>
              </p>
            </SpotlightCard>
            </div>
          </Reveal>
        </section>

        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">Don&apos;t be the next one</p>
            <h2 className="dxd-h2">Find out if your app has the same gap.</h2>
            <p className="dxd-lede">
              The RLS pattern behind CVE-2025-48757 is check 1 of the 16 ShipLock runs against
              your live Supabase project, on every audit and every automated pass after.
            </p>
            <div style={{ marginTop: 20 }}>
              <Link href="/#pricing" className="dxd-btn dxd-btn-paper">
                See pricing
              </Link>
            </div>
          </Reveal>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
          </span>
          <span>
            <Link href="/">Home</Link> · <Link href="/owasp">OWASP Top 10</Link> ·{" "}
            <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link>
          </span>
        </footer>
      </div>
    </main>
  );
}
