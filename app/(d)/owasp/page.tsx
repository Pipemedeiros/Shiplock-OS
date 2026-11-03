import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Real educational content page, grounded in the official OWASP Top
// 10:2025 (fetched directly from owasp.org/Top10/2025/ during research, not
// reconstructed from memory or a secondary source). Each "ShipLock coverage"
// line follows the same code as /coverage (rewritten 2026-10-20, when this page
// still described the retired external scanner and claimed injection checks
// that had been withdrawn): the repository audit and merge check
// (lib/agent, lib/graph), source scanning (lib/deep/githubRun.ts), the live
// site (lib/security/exposedPathsRun.ts), and, only when a Supabase project URL
// and anon key are connected, the endpoint scan (lib/scanner.ts).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "OWASP Top 10 for AI-built apps",
  description:
    "The OWASP Top 10:2025, mapped honestly to what an external scanner can and cannot check, including the categories no tool can automate and what to ask instead.",
};


const CATEGORIES = [
  {
    id: "A01",
    name: "Broken Access Control",
    body: "Someone can see or change data they shouldn't be able to reach, a stranger reading another user's rows, or an anonymous request hitting an endpoint that should require login. In an AI-written app this is almost always a table with Row Level Security left off, or a route that never checks who is calling.",
    coverage:
      "the category ShipLock is built around. From your repository: every route traced to whether it identifies its caller and narrows the query to that caller, routes that change data without identifying the caller, and mass assignment; the merge check flags a new route that reaches data anonymously. With a Supabase project URL and anon key connected: tables readable without signing in, rows readable across users, the auth admin endpoint, and public storage buckets. With read-only database access: the policies themselves.",
  },
  {
    id: "A02",
    name: "Security Misconfiguration",
    body: "Settings shipped at their insecure defaults and never revisited, wildcard CORS, no HTTPS redirect, verbose error pages, missing security headers. Nothing was \"hacked\"; nobody ever changed the setting.",
    coverage:
      "covered on your live site: a readable .env file, Git metadata, database dumps and credential files at fixed paths, public source maps, and whether framing and HTTPS-only are enforced (reported as information). From your repository: Next.js configuration that hands a server value to client builds, and GitHub Actions workflows with no stated permissions. With a Supabase endpoint connected: its CORS policy.",
  },
  {
    id: "A03",
    name: "Software Supply Chain Failures",
    body: "A dependency you pulled in, sometimes one an AI coding tool invented or mis-typed, turns out to be malicious, compromised, or simply doesn't exist and is sitting there waiting for someone to register it. See our incidents page for a real 2025 npm worm that spread exactly this way.",
    coverage:
      "partial. Dependencies matched by package and version against public vulnerability advisories, and third-party GitHub Actions pinned to a moveable tag rather than a commit. Whether the vulnerable code path is reachable in your app is not determined.",
  },
  {
    id: "A04",
    name: "Cryptographic Failures",
    body: "Sensitive data transmitted or stored without adequate encryption, plaintext traffic, weak key management, secrets that aren't actually secret.",
    coverage:
      "partial. A token or one-time code built from Math.random(), a credential carried in a URL query string, and secret keys committed to the repository or shipped in your site's JavaScript. Encryption at rest and key management are not assessed.",
  },
  {
    id: "A05",
    name: "Injection",
    body: "Crafted input reaches a query or command in a way the developer didn't intend, the classic SQL injection, plus its modern variants.",
    coverage:
      "mostly not covered. SQL, command and cross-site scripting pattern checks were withdrawn: a per-file pattern cannot tell whether the value reaching a dangerous call is attacker controlled. With a Supabase endpoint connected, one probe checks whether a malformed filter makes the API return a raw database error.",
  },
  {
    id: "A06",
    name: "Insecure Design",
    body: "The vulnerability isn't a bug, it's the architecture. Missing threat modeling, a business-logic flow that was never designed with abuse in mind.",
    coverage:
      "not covered. Business logic is a matter of intent, and no automated read of the code can judge intent. The questions further down are what to ask instead.",
  },
  {
    id: "A07",
    name: "Authentication Failures",
    body: "Weak session handling, credential stuffing with no resistance, brute-forceable logins.",
    coverage:
      "partial. From your repository: whether each route identifies its caller, where a missing login check shows up. A service-role key in the repository or the shipped JavaScript is reported as critical. With a Supabase endpoint connected: whether five failed logins in a row are throttled, and whether a public key can reach the admin user list.",
  },
  {
    id: "A08",
    name: "Software or Data Integrity Failures",
    body: "Unsigned or unverified updates, a compromised build pipeline, deserializing data from a source you shouldn't trust.",
    coverage:
      "partial. A pull_request_target workflow that runs a pull request's own code, third-party actions on moveable tags, and dependency advisories. Unsigned updates and insecure deserialization are not checked.",
  },
  {
    id: "A09",
    name: "Security Logging and Alerting Failures",
    body: "An incident happens and nobody finds out, no logs, no alerting, no one watching.",
    coverage:
      "we don't check whether your app logs correctly. Watching is what ShipLock adds: the merge check on every pull request the GitHub App reports, source checks at most every 48 hours, the live site every 48 hours and after a reported production deploy, and with a Supabase endpoint connected an hourly pass of its critical checks. New findings appear in your dashboard and to your agent.",
  },
  {
    id: "A10",
    name: "Mishandling of Exceptional Conditions",
    body: "Error handling that leaks internals, or business logic that fails open instead of closed when something goes wrong.",
    coverage:
      "partial. With a Supabase endpoint connected: whether a malformed request returns file paths, line numbers or internal error detail.",
  },
];

// Real, generic, usable-today guidance for exactly the categories above
// that CATEGORIES already marks as uncovered or partial —
// deliberately not scan-specific, since there's no real check behind it.
// This is the on-ramp to a future GitHub-integrated, personalized version
// of the same idea (source access + the owner's own review prompts) —
// not a placeholder for that, a real generic version usable right now.
const NOT_SCANNABLE = [
  {
    surface: "Business logic (A06 · Insecure Design)",
    intro:
      "No scanner can read your intent, only a human, or an AI agent walked through your actual flows, can. For every flow that touches money, auth, or another user's data, paste this to your coding agent:",
    prompt:
      "Walk through [flow name] end to end. For each step: what happens if this request arrives twice? Out of order? From a user who shouldn't be able to reach this step yet? Does the server ever trust a price, role, quantity, or user ID that the client sent, instead of computing or verifying it server-side?",
  },
  {
    surface: "Build & deploy integrity (A08)",
    intro:
      "This is about whether what ships is what you reviewed, not a database question, a pipeline one:",
    prompt:
      "Review my deploy setup: is there a lockfile committed and enforced (not just present)? Does main auto-deploy without any review step? For every webhook receiver in this codebase (Stripe, GitHub, etc.), confirm the signature is actually verified before the payload is trusted, list any that aren't.",
  },
  {
    surface: "Logging & alerting (A09)",
    intro:
      "You don't need a SIEM. You need to know if something changed. Ask your agent to check for the absence of these, not add anything heavy:",
    prompt:
      "Does this app log failed login attempts anywhere I'd ever actually look? Is there any alert if signups or database reads spike far above normal in a short window? If a background job or webhook handler throws, does that failure go anywhere besides a log I'd have to think to check?",
  },
];

export default function OwaspPage() {
  return (
    <main className="v3">
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top" aria-label="Main">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
            <div className="v3-nav-links">
              <Link className="v3-nav-secondary" href="/coverage">What it covers</Link>
              <Link className="v3-nav-secondary" href="/incidents">Real incidents</Link>
              <Link href="/auth" className="v3-btn v3-btn-sm v3-ondark">Sign in</Link>
            </div>
          </nav>

          <header className="v3-hero">
            <p className="v3-vr-kicker">Learn the risks</p>
            <h1 className="v3-serif">The OWASP Top 10:2025, in plain English.</h1>
            <p>
              OWASP is the industry-standard list of the ten risk categories behind the most
              real-world application breaches. Here is what each one means, what it looks like in an
              app whose code was largely AI-written, and which parts of ShipLock cover it today and
              which don&apos;t.
            </p>
          </header>
        </div>
      </div>

      <div className="v3-shell v3-scope">
        {CATEGORIES.map((c) => (
          <section key={c.id} className="v3-scope-area" aria-labelledby={`cat-${c.id}`}>
            <div className="v3-scope-hd">
              <span className="v3-mono">{c.id}</span>
              <h2 id={`cat-${c.id}`} className="v3-serif">{c.name}</h2>
            </div>
            <p className="v3-scope-lead">{c.body}</p>
            <div className="v3-card v3-scope-limit">
              <p className="v3-eyebrow">ShipLock coverage</p>
              <p>{c.coverage.charAt(0).toUpperCase() + c.coverage.slice(1)}</p>
            </div>
          </section>
        ))}

        <section id="not-scannable" className="v3-scope-area" aria-labelledby="not-scannable-title">
          <p className="v3-eyebrow">Honest about the gap</p>
          <h2 id="not-scannable-title" className="v3-serif v3-owasp-h2">What we can&apos;t check, and what to ask instead.</h2>
          <p className="v3-scope-lead">
            Business logic, deploy integrity, and whether anyone would notice if something went
            wrong are judgment calls, not configuration flags. We&apos;d rather hand you the
            questions than pretend we already ask them for you.
          </p>
          <div className="v3-stack">
            {NOT_SCANNABLE.map((n) => (
              <div className="v3-card v3-card-p" key={n.surface}>
                <h3 className="v3-owasp-h3">{n.surface}</h3>
                <p className="v3-small" style={{ marginTop: 6 }}>{n.intro}</p>
                <pre className="v3-code v3-owasp-prompt">{n.prompt}</pre>
              </div>
            ))}
          </div>
        </section>

        <section id="get-started" aria-labelledby="get-started-title">
          <h2 id="get-started-title" className="v3-serif v3-owasp-h2">See what these look like in your app.</h2>
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
          <Link href="/">Home</Link> · <Link href="/incidents">Real incidents</Link> ·{" "}
          <Link href="/terms">Terms</Link> · <Link href="/privacy">Privacy</Link>
        </footer>
      </div>
    </main>
  );
}
