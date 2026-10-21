import Link from "next/link";
import { GoogleOneTap } from "@/components/GoogleOneTap";
import { ArrowRight } from "lucide-react";
import { LockMark } from "@/components/d/Brand";
import { ReasoningAnimation } from "@/components/v3/ReasoningAnimation";
import { LayersAnimation } from "@/components/v3/LayersAnimation";

export const metadata = {
  title: "ShipLock: security monitoring that opens the pull request",
  description:
    "ShipLock maps your routes to the data they reach, finds the missing check, and opens the fix as a pull request. Code, live configuration and traffic, read together.",
};

/**
 * The landing page.
 *
 * No pricing and no paywall while the MVP is open. One call to action, which
 * goes to GitHub. The reader is a founder or an engineer at a startup with
 * customers and no security hire; the copy assumes they know what an
 * authorization check is and does not explain it to them.
 */
export default function Landing() {
  return (
    <main className="v3">
      <div className="v3-band">
        <GoogleOneTap />
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <span className="v3-mark"><LockMark size={20} /> ShipLock</span>
            <div className="v3-nav-links">
              <a className="v3-nav-secondary" href="#how">How it works</a>
              <Link className="v3-nav-secondary" href="/coverage">What it covers</Link>
              <Link href="/auth">Sign in</Link>
              <Link href="/onboarding" className="v3-btn v3-btn-sm v3-ondark">Get started</Link>
            </div>
          </nav>

          <div className="v3-grid-2" style={{ gap: 48, alignItems: "center", padding: "68px 0 78px" }}>
            <div>
              <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>
                Application security for teams without a security hire
              </p>
              <h1 className="v3-serif" style={{ fontSize: 44, lineHeight: 1.12, margin: "16px 0 20px" }}>
                Security monitoring that opens the pull request.
              </h1>
              <p style={{ fontSize: 17.5, color: "var(--muted-navy)", maxWidth: 560 }}>
                ShipLock maps your routes to the data they reach, finds the check that is missing, and
                opens the fix as a pull request. It also tells you what it could not read.
              </p>
              <div className="v3-row" style={{ marginTop: 30 }}>
                <Link href="/onboarding" className="v3-btn v3-primary">
                  Get started <ArrowRight size={15} />
                </Link>
                <span className="v3-mono" style={{ fontSize: 12.5, color: "var(--muted-navy)" }}>
                  Free in preview · read only until you approve a change
                </span>
              </div>
            </div>

            <ReasoningAnimation />
          </div>
        </div>
      </div>

      {/* ── how it works ─────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="how">
        <div className="v3-section-hd">
          <p className="v3-eyebrow">How it works</p>
          <h2 className="v3-serif">Map, trace, fix.</h2>
        </div>
        <div className="v3-argument">
          {[
            { n: "01", h: "Map", b: "Routes, auth, tables and providers, inferred from your code. No questionnaire." },
            { n: "02", h: "Trace", b: "Who can call each route, and what narrows the query to them. Every finding cites the file it came from." },
            { n: "03", h: "Fix", b: "A pull request you review and merge. ShipLock never merges or deploys." },
          ].map((c) => (
            <div key={c.n}>
              <p className="v3-eyebrow">{c.n}</p>
              <h3>{c.h}</h3>
              <p className="v3-sub" style={{ fontSize: 14.5 }}>{c.b}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── the thesis ───────────────────────────────────────────────────── */}
      <div style={{ background: "var(--sand)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div className="v3-shell v3-section">
          <div className="v3-grid-2" style={{ gap: 48, alignItems: "center" }}>
            <div>
              <p className="v3-eyebrow">Why code alone is not enough</p>
              <h2 className="v3-serif" style={{ fontSize: 29, margin: "11px 0 14px" }}>Code is half the picture.</h2>
              <p className="v3-sub" style={{ fontSize: 15.5 }}>
                A route can look correct and still leak. Row policies live in your database, not your repository. Your
                live site can call addresses your repository does not have. A small hole matters when it is hit 2,000
                times a minute. Connect your database read only, confirm your app&apos;s address and add the traffic
                snippet, and ShipLock reads them together.
              </p>
            </div>
            <LayersAnimation />
          </div>
        </div>
      </div>

      {/* ── evidence ─────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="evidence">
        <div className="v3-section-hd">
          <p className="v3-eyebrow">Why access control</p>
          <h2 className="v3-serif">The bugs we look for keep shipping.</h2>
        </div>

        <div className="v3-grid-3" style={{ gap: 16 }}>
          {[
            {
              tag: "CVE-2025-48757",
              source: "NVD",
              href: "https://nvd.nist.gov/vuln/detail/CVE-2025-48757",
              head: "170+ live apps, one missing row policy",
              body: "AI-built apps shipped tables without row-level security. The public key read every row.",
            },
            {
              tag: "Mythos IDOR benchmark",
              source: "Semgrep",
              href: "https://semgrep.dev/blog/2026/mythos-idor-benchmark/",
              head: "Ownership bugs resist pattern matching",
              body: "The code is correct in isolation and wrong for the caller. So ShipLock reasons over routes and schema together.",
            },
            {
              tag: "OWASP Top 10:2025",
              source: "OWASP",
              href: "https://owasp.org/Top10/",
              head: "Broken access control, still number one",
              body: "The rule it breaks is specific to your product, which is where generic scanners have the least to say.",
            },
          ].map((c) => (
            <a key={c.tag} href={c.href} target="_blank" rel="noopener noreferrer" className="v3-evidence">
              <div className="v3-between">
                <span className="v3-mono" style={{ fontSize: 11.5, color: "var(--bronze)" }}>{c.tag}</span>
                <span className="v3-small">{c.source}</span>
              </div>
              <h3 style={{ fontSize: 15.5, fontWeight: 500, margin: "10px 0 8px" }}>{c.head}</h3>
              <p className="v3-sub" style={{ fontSize: 13.5 }}>{c.body}</p>
              <span className="v3-small v3-evidence-go">Read the source &rarr;</span>
            </a>
          ))}
        </div>

        <p className="v3-small" style={{ marginTop: 18 }}>
          More in <Link href="/incidents">incidents</Link> and <Link href="/owasp">the OWASP mapping</Link>.
        </p>
      </div>

      {/* ── close ────────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" style={{ textAlign: "center" }}>
        <h2 className="v3-serif" style={{ fontSize: 30, marginBottom: 12 }}>Point it at a repository.</h2>
        <p className="v3-sub" style={{ maxWidth: 480, margin: "0 auto 26px" }}>
          See every path the audit found to your data, and what it could not read.
        </p>
        <Link href="/onboarding" className="v3-btn v3-primary">
          Get started <ArrowRight size={15} />
        </Link>
      </div>

      <div className="v3-band">
        <div className="v3-shell" style={{ paddingTop: 26, paddingBottom: 26, fontSize: 13, color: "var(--muted-navy)" }}>
          <div className="v3-between">
            <span className="v3-row" style={{ gap: 8 }}><LockMark size={15} /> © {new Date().getFullYear()} ShipLock</span>
            <span className="v3-row" style={{ gap: 20 }}>
              <Link href="/coverage">Coverage</Link>
              <Link href="/owasp">OWASP</Link>
              <Link href="/incidents">Incidents</Link>
              <Link href="/privacy">Privacy</Link>
              <Link href="/terms">Terms</Link>
            </span>
          </div>
        </div>
      </div>
    </main>
  );
}
