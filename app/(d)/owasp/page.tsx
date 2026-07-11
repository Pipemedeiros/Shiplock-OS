import Link from "next/link";
import { ProximityText, Reveal, RevealList, SpotlightCard } from "@/components/d/bits";
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
      "Partial: our dependency slop-squatting check catches invented or suspiciously new packages in package.json — but only if you add your app's live URL on the scan form (optional; without it, there's no real package.json for this check to read, since your Supabase project URL never serves one). Even then, it does not check known-CVE databases against your installed dependency versions — that needs source access, which is a roadmap item (GitHub App integration), not live today.",
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

// Real, generic, usable-today guidance for exactly the categories above
// that CATEGORIES already marks as uncovered or partial (A06/A08/A09) —
// deliberately not scan-specific, since there's no real check behind it.
// This is the on-ramp to a future GitHub-integrated, personalized version
// of the same idea (source access + the owner's own review prompts) —
// not a placeholder for that, a real generic version usable right now.
const NOT_SCANNABLE = [
  {
    surface: "Business logic (A06 · Insecure Design)",
    intro:
      "No scanner can read your intent — only a human, or an AI agent walked through your actual flows, can. For every flow that touches money, auth, or another user's data, paste this to your coding agent:",
    prompt:
      "Walk through [flow name] end to end. For each step: what happens if this request arrives twice? Out of order? From a user who shouldn't be able to reach this step yet? Does the server ever trust a price, role, quantity, or user ID that the client sent, instead of computing or verifying it server-side?",
  },
  {
    surface: "Build & deploy integrity (A08)",
    intro:
      "This is about whether what ships is what you reviewed — not a database question, a pipeline one:",
    prompt:
      "Review my deploy setup: is there a lockfile committed and enforced (not just present)? Does main auto-deploy without any review step? For every webhook receiver in this codebase (Stripe, GitHub, etc.), confirm the signature is actually verified before the payload is trusted — list any that aren't.",
  },
  {
    surface: "Logging & alerting (A09)",
    intro:
      "You don't need a SIEM. You need to know if something changed. Ask your agent to check for the absence of these, not add anything heavy:",
    prompt:
      "Does this app log failed login attempts anywhere I'd ever actually look? Is there any alert if signups or database reads spike far above normal in a short window? If a background job or webhook handler throws, does that failure go anywhere besides a Vercel log I'd have to think to check?",
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
                <ProximityText text="The OWASP Top 10:2025, in plain English." />
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
            <RevealList step={60}>
              {CATEGORIES.map((c) => (
                <div className="dxd-step" key={c.id}>
                  <span className="dxd-step-num dxd-serif">{c.id}</span>
                  <div>
                    <h3>{c.name}</h3>
                    <p>{c.body}</p>
                    <p className="dxd-keynote" style={{ marginTop: 8 }}>
                      ShipLock coverage — {c.coverage}
                    </p>
                  </div>
                </div>
              ))}
            </RevealList>
          </div>
        </section>

        <section className="dxd-section" id="not-scannable">
          <Reveal>
            <p className="dxd-eyebrow">Honest about the gap</p>
            <h2 className="dxd-h2">What we can&apos;t scan — and what to ask instead.</h2>
            <p className="dxd-lede" style={{ marginBottom: 8 }}>
              A handful of the categories above have no real automated check behind them, by
              nature — business logic, deploy integrity, and whether anyone would notice if
              something went wrong are judgment calls, not configuration flags. We&apos;d rather
              hand you the questions than pretend we already ask them for you.
            </p>
          </Reveal>
          <div className="dxd-surfaces">
            <RevealList step={90}>
              {NOT_SCANNABLE.map((n) => (
                <SpotlightCard className="dxd-surface" key={n.surface}>
                  <h3>{n.surface}</h3>
                  <p>{n.intro}</p>
                  <pre className="dxd-code" style={{ marginTop: 12, whiteSpace: "pre-wrap" }}>
                    {n.prompt}
                  </pre>
                </SpotlightCard>
              ))}
            </RevealList>
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
