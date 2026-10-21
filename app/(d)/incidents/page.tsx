import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Real incidents, not hypotheticals — every claim here is sourced (NVD,
// CISA, vendor security blogs, or the CVE record itself) and linked.
// Deliberately honest about scope. Each "ShipLock coverage" line follows the
// same code as /coverage (rewritten 2026-10-20, when this page still described
// the retired 16-check scanner and said dependency advisories were not live).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Real incidents in AI-built apps",
  description:
    "Sourced writeups of real breaches in vibe-coded apps: CVE-2025-48757 (170+ Lovable apps exposed via missing RLS), the npm supply-chain worm, and CVE-2025-29927.",
};


type Incident = {
  kicker: string; title: string; paras: React.ReactNode[]; coverage: string;
  sources: { href: string; label: string }[];
};

const INCIDENTS: Incident[] = [
  {
    kicker: "The anchor case",
    title: "CVE-2025-48757, 170+ real apps, exactly this pattern.",
    paras: [
      <>
        In May 2025, security researcher Matt Palmer disclosed that 303 endpoints across 170 real
        apps built with Lovable, 10.3% of the projects he analyzed, could be read or written by
        anyone, unauthenticated, because Row Level Security was left off. NVD rated it CVSS 9.3,
        critical, CWE-863 (incorrect authorization). NVD&apos;s own description: &ldquo;An
        insufficient database Row-Level Security policy in Lovable&hellip; allows remote
        unauthenticated attackers to read or write to arbitrary database tables of generated
        sites.&rdquo;
      </>,
      <>
        One detail worth sitting with: the vendor&apos;s own response disputed that this was a
        Lovable bug at all, their position was that customers are responsible for protecting
        their own application data. Whether or not you think that&apos;s fair, it&apos;s the
        reality every builder on every AI coding tool ships into. RLS is off by default on new
        Supabase tables, and nobody except you is going to turn it on.
      </>,
    ],
    coverage:
      "This is the pattern ShipLock is built around. From your repository: routes that reach a table without identifying the caller or narrowing the query to them. With a Supabase project URL and anon key connected: tables without row-level security and tables readable without signing in, checked every hour. With read-only database access: the policies themselves.",
    sources: [
      { href: "https://nvd.nist.gov/vuln/detail/CVE-2025-48757", label: "NVD: CVE-2025-48757" },
      { href: "https://supabase.com/blog/supabase-security-2025-retro", label: "Supabase's own 2025 security retro" },
    ],
  },
  {
    kicker: "Supply chain",
    title: "Shai-Hulud, a self-replicating npm worm.",
    paras: [
      <>
        Starting September 2025, a worm nicknamed Shai-Hulud spread through the npm registry:
        attackers compromised a maintainer&apos;s account via phishing, published malicious
        versions of their packages, then used the stolen credentials to infect every other
        package that maintainer owned, self-replicating without further human involvement. CISA
        issued an alert. A second, more aggressive wave (&ldquo;Shai-Hulud 2.0&rdquo;) hit in
        November 2025, compromising hundreds more packages and, in some cases, attempting to
        destroy the infected machine&apos;s home directory.
      </>,
    ],
    coverage:
      "Partial. Your dependencies are matched by package and version against public vulnerability advisories, so a version known to be compromised is reported once an advisory names it. A package that turns malicious before any advisory exists is not caught, and neither is what it did after installation.",
    sources: [
      { href: "https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem", label: "CISA alert" },
      { href: "https://unit42.paloaltonetworks.com/npm-supply-chain-attack/", label: "Palo Alto Unit 42 writeup" },
    ],
  },
  {
    kicker: "Framework",
    title: "CVE-2025-29927, Next.js middleware bypass.",
    paras: [
      <>
        A CVSS 9.1 vulnerability disclosed in March 2025: a crafted request header
        (<code>x-middleware-subrequest</code>) could trick vulnerable Next.js versions into
        skipping middleware entirely, including whatever auth checks your middleware was supposed
        to enforce.
      </>,
      <>
        Vercel confirmed apps hosted on Vercel were never affected by this one, the
        platform&apos;s own request handling doesn&apos;t expose the vulnerable path.
      </>,
    ],
    coverage:
      "Partial. If your repository pins an affected Next.js version, the same check against public vulnerability advisories reports it. Whether your host exposed the vulnerable path is not determined, and we never send the header to your site to find out.",
    sources: [
      { href: "https://nvd.nist.gov/vuln/detail/CVE-2025-29927", label: "NVD: CVE-2025-29927" },
      { href: "https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/", label: "Datadog Security Labs writeup" },
    ],
  },
];

export default function IncidentsPage() {
  return (
    <main className="v3">
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top" aria-label="Main">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
            <div className="v3-nav-links">
              <Link className="v3-nav-secondary" href="/coverage">What it covers</Link>
              <Link className="v3-nav-secondary" href="/owasp">OWASP Top 10</Link>
              <Link href="/auth" className="v3-btn v3-btn-sm v3-ondark">Sign in</Link>
            </div>
          </nav>

          <header className="v3-hero">
            <p className="v3-vr-kicker">This already happened</p>
            <h1 className="v3-serif">Real incidents, not hypotheticals.</h1>
            <p>
              Every claim on this page is sourced and linked, NVD, CISA, or the vendor&apos;s own
              security writeup. No invented statistics.
            </p>
          </header>
        </div>
      </div>

      <div className="v3-shell v3-scope">
        {INCIDENTS.map((i, n) => (
          <section key={i.title} className="v3-scope-area" aria-labelledby={`incident-${n}`}>
            <p className="v3-eyebrow">{i.kicker}</p>
            <h2 id={`incident-${n}`} className="v3-serif v3-owasp-h2">{i.title}</h2>
            {i.paras.map((para, k) => <p key={k} className="v3-incident-p">{para}</p>)}
            <div className="v3-card v3-scope-limit">
              <p className="v3-eyebrow">ShipLock coverage</p>
              <p>{i.coverage}</p>
            </div>
            <p className="v3-small v3-incident-src">
              {i.sources.map((src, k) => (
                <span key={src.href}>
                  {k > 0 ? " · " : null}
                  <a href={src.href} target="_blank" rel="noopener noreferrer" className="v3-vr-link">{src.label}</a>
                </span>
              ))}
            </p>
          </section>
        ))}

        <section id="get-started" aria-labelledby="get-started-title">
          <h2 id="get-started-title" className="v3-serif v3-owasp-h2">Find out if your app has the same gap.</h2>
          <p className="v3-scope-lead">
            Connect GitHub and ShipLock reads your repository, then your live site and database if
            you add them. Every limit is stated on the scope page.
          </p>
          <div className="v3-row">
            <Link href="/onboarding" className="v3-btn v3-primary">Get started</Link>
            <Link href="/coverage" className="v3-btn v3-ghost">What it covers</Link>
          </div>
        </section>

        <footer className="v3-owasp-foot v3-small">
          <Link href="/">Home</Link> · <Link href="/owasp">OWASP Top 10</Link> ·{" "}
          <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link>
        </footer>
      </div>
    </main>
  );
}
