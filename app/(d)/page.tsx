import Link from "next/link";
import { GoogleOneTap } from "@/components/GoogleOneTap";
import { ArrowRight } from "lucide-react";
import { LockMark } from "@/components/d/Brand";
import { AgentSession } from "@/components/v3/AgentSession";
import { AgentConnect } from "@/components/v3/AgentConnect";
import { LayersAnimation } from "@/components/v3/LayersAnimation";

export const metadata = {
  title: "ShipLock: a security engineer your coding agent can call",
  description:
    "ShipLock reads your repository, live stack and traffic and hands your coding agent the facts over MCP. Your agent proposes the fix; you click to open the pull request.",
  alternates: { types: { "text/plain": "/llms.txt" } },
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
              <a className="v3-nav-secondary" href="#agents">For agents</a>
              <Link className="v3-nav-secondary" href="/coverage">What it covers</Link>
              <Link href="/auth">Sign in</Link>
              <Link href="/onboarding" className="v3-btn v3-btn-sm v3-ondark">Get started</Link>
            </div>
          </nav>

          <div className="v3-split">
            <div>
              <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>
                Security for teams that ship with agents
              </p>
              <h1 className="v3-serif v3-hero-h">
                A security engineer your coding agent can call.
              </h1>
              <p className="v3-hero-sub">
                ShipLock reads your repository, live stack and traffic, and hands your agent the facts over MCP,
                including what it could not read. Your agent proposes the fix. You click to open the pull request.
              </p>
              <div className="v3-row" style={{ marginTop: 30, gap: 14 }}>
                <Link href="/onboarding" className="v3-btn v3-primary">
                  Get started <ArrowRight size={15} />
                </Link>
                <a href="#agents" className="v3-btn v3-ondark">Connect your agent</a>
              </div>
              <p className="v3-mono v3-hero-note">Free in preview · read only until you click</p>
            </div>

            <AgentSession />
          </div>
        </div>
      </div>

      {/* ── the loop ─────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="how">
        <div className="v3-section-hd">
          <p className="v3-eyebrow">How it works</p>
          <h2 className="v3-serif">One loop. Three hands on it.</h2>
        </div>
        <ol className="v3-rail">
          {[
            { h: "Read", who: "ShipLock", b: "Every deterministic check. Unread stays unread." },
            { h: "Attack", who: "Your agent", b: "Proposes attacks, checked against the quoted lines." },
            { h: "Map", who: "ShipLock", b: "Wrong routes and what they reach." },
            { h: "Fix", who: "You", b: "A pull request on your click, with a receipt. ShipLock never merges or deploys." },
            { h: "Watch", who: "ShipLock", b: "PR checks, rechecks, live config and traffic." },
          ].map((c, i) => (
            <li key={c.h} className="v3-rail-step">
              <span className="v3-rail-n v3-mono" aria-hidden="true">{String(i + 1).padStart(2, "0")}</span>
              <h3 className="v3-serif">{c.h}</h3>
              <span className={`v3-who v3-mono v3-who-${c.who === "ShipLock" ? "us" : c.who === "You" ? "you" : "agent"}`}>{c.who}</span>
              <p className="v3-sub">{c.b}</p>
            </li>
          ))}
        </ol>
      </div>

      {/* ── for agents ───────────────────────────────────────────────────── */}
      <div className="v3-band" id="agents">
        <div className="v3-shell v3-section">
          <div className="v3-split" style={{ alignItems: "start" }}>
            <div>
              <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>For your agent</p>
              <h2 className="v3-serif" style={{ fontSize: 32, margin: "12px 0 16px" }}>Built to be read by machines.</h2>
              <p className="v3-hero-sub" style={{ fontSize: 15.5 }}>
                Your agent does the thinking, on your subscription. ShipLock gives it typed facts with sources and
                re-reads every line it cites.
              </p>
              <ul className="v3-facts">
                <li><b>Hosted MCP</b><span className="v3-mono">shiplock.dev/api/mcp/server</span></li>
                <li><b>Read only tools</b><span>No scan, write or merge tool</span></li>
                <li><b>Plain text</b><a className="v3-mono" href="/llms.txt">/llms.txt</a></li>
              </ul>
            </div>
            <AgentConnect />
          </div>
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
                times a minute. Connect them, read only, and ShipLock reads them together.
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
              body: "Correct in isolation, wrong for the caller.",
            },
            {
              tag: "OWASP Top 10:2025",
              source: "OWASP",
              href: "https://owasp.org/Top10/",
              head: "Broken access control, still number one",
              body: "The rule it breaks is specific to your product.",
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
        <h2 className="v3-serif" style={{ fontSize: 30, marginBottom: 12 }}>Point your agent at it.</h2>
        <p className="v3-sub" style={{ maxWidth: 480, margin: "0 auto 26px" }}>
          Every path to your data, and what was not read.
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
