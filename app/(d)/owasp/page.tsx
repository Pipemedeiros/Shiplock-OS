import Link from "next/link";
import { Reveal } from "@/components/d/bits";
import { LockMark } from "@/components/d/Brand";

// Real educational content page — grounded in the official OWASP Top
// 10:2025 (fetched directly from owasp.org/Top10/2025/ during research, not
// reconstructed from memory or a secondary source). Each entry's "ShipLock
// coverage" line is honest about the gap between the category and what our
// 16 checks (lib/scanner.ts) actually test — several categories are
// genuinely uncovered today, and that's stated plainly rather than
// stretched into a false mapping.
export const dynamic = "force-dynamic";

const CATEGORIES = [
  {
    id: "A01",
    name: "Broken Access Control",
    body: "Someone can see or change data they shouldn't be able to reach — a stranger reading another user's rows, or an anonymous request hitting an endpoint that should require login. In a vibe-coded app this is almost always a Supabase table with Row Level Security left off, or off-by-default.",
    coverage:
      "This is the category ShipLock is built around. Covered directly: row-level security, unauthenticated table access, IDOR on user data, auth admin endpoint exposure, and public storage buckets.",
  },
  {
    id: "A02",
    name: "Security Misconfiguration",
    body: "Settings shipped at their insecure defaults and never revisited — wildcard CORS, no HTTPS redirect, verbose error pages, missing security headers. Nothing was \"hacked\"; nobody ever changed the setting.",
    coverage:
      "Covered directly: CORS wildcard policy, HTTPS enforcement, bot-protection headers, secrets & .env exposure, service-role key exposure.",
  },
  {
    id: "A03",
    name: "Software Supply Chain Failures",
    body: "A dependency you pulled in — sometimes one an AI coding tool invented or mis-typed — turns out to be malicious, compromised, or simply doesn't exist and is sitting there waiting for someone to register it. See our incidents page for a real 2025 npm worm that spread exactly this way.",
    coverage:
      "Partial: our dependency slop-squatting check catches invented or suspiciously new packages in your package.json. It does not check known-CVE databases against your installed dependency versions — that needs source access, which is a roadmap item (GitHub App integration), not live today.",
  },
  {
    id: "A04",
    name: "Cryptographic Failures",
    body: "Sensitive data transmitted or stored without adequate encryption — plaintext traffic, weak key management, secrets that aren't actually secret.",
    coverage:
      "Partial: our HTTPS enforcement check covers encryption in transit. We don't assess encryption at rest or key-management practices — Supabase manages that layer internally, outside what an anon-key scan can see.",
  },
  {
    id: "A05",
    name: "Injection",
    body: "Crafted input reaches a query or command in a way the developer didn't intend — the classic SQL injection, plus its modern variants.",
    coverage:
      "Partial: our input validation check probes whether a crafted query parameter leaks a raw SQL error, a strong signal of injection risk. It's a signal, not exhaustive fuzzing of every endpoint and parameter.",
  },
  {
    id: "A06",
    name: "Insecure Design",
    body: "The vulnerability isn't a bug — it's the architecture. Missing threat modeling, a business-logic flow that was never designed with abuse in mind.",
    coverage:
      "Not covered. This is exactly the kind of thing a real audit's methodology catches and an automated external scan structurally can't — no check here today, and we're not going to pretend otherwise.",
  },
  {
    id: "A07",
    name: "Authentication Failures",
    body: "Weak session handling, credential stuffing with no resistance, brute-forceable logins.",
    coverage:
      "Covered directly: login rate limiting, auth admin endpoint exposure, service-role key exposure (a compromised master key is an authentication failure at the most severe end).",
  },
  {
    id: "A08",
    name: "Software or Data Integrity Failures",
    body: "Unsigned or unverified updates, a compromised build pipeline, deserializing data from a source you shouldn't trust.",
    coverage:
      "Not covered today. Needs visibility into your build/deploy pipeline, which is the not-yet-built GitHub App and Vercel integrations on our roadmap, not the current URL-and-anon-key scan.",
  },
  {
    id: "A09",
    name: "Security Logging and Alerting Failures",
    body: "An incident happens and nobody finds out — no logs, no alerting, no one watching.",
    coverage:
      "We don't scan whether your own app logs correctly. But this is the category our continuous-monitoring product exists to backstop for you specifically: deploy-triggered re-scans, an hourly critical-check pass, and alerts the moment something new appears.",
  },
  {
    id: "A10",
    name: "Mishandling of Exceptional Conditions",
    body: "Error handling that leaks internals, or business logic that fails open instead of closed when something goes wrong.",
    coverage:
      "Partial: our stack trace exposure check catches the specific case of a malformed request leaking file paths, line numbers, or internal error detail back to the client.",
  },
];

export default function OwaspPage() {
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
              <Link href="/incidents">Real incidents</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>

          <header className="dxd-hero" style={{ gridTemplateColumns: "1fr" }}>
            <div>
              <p className="dxd-eyebrow">Learn the risks</p>
              <h1 className="dxd-display" style={{ fontSize: "clamp(32px,5vw,52px)" }}>
                The OWASP Top 10:2025, in plain English.
              </h1>
              <p className="dxd-lede">
                OWASP is the industry-standard list of the ten risk categories that cause the
                most real-world application breaches. This page explains each one for people who
                didn&apos;t write their own backend by hand — what it means, what it looks like in
                a Lovable/Bolt/Cursor/v0 + Supabase app, and, honestly, which of our 16 checks
                actually cover it today and which don&apos;t yet.
              </p>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        <section className="dxd-section">
          <div className="dxd-steps" style={{ flexDirection: "column" }}>
            {CATEGORIES.map((c) => (
              <Reveal key={c.id}>
                <div className="dxd-step">
                  <span className="dxd-step-num dxd-serif">{c.id}</span>
                  <div>
                    <h3>{c.name}</h3>
                    <p>{c.body}</p>
                    <p className="dxd-keynote" style={{ marginTop: 8 }}>
                      ShipLock coverage — {c.coverage}
                    </p>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        <section className="dxd-section" id="get-started">
          <Reveal>
            <p className="dxd-eyebrow">Want the honest scan</p>
            <h2 className="dxd-h2">See exactly what these look like in your app.</h2>
            <p className="dxd-lede">
              ShipLock runs 16 real checks against your live Supabase project, named precisely —
              no invented categories, no vague grades.
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
            <Link href="/">Home</Link> · <Link href="/incidents">Real incidents</Link> ·{" "}
            <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link>
          </span>
        </footer>
      </div>
    </main>
  );
}
