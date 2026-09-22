import Link from "next/link";
import { ArrowRight, Check } from "lucide-react";
import { LockMark } from "@/components/d/Brand";
import { ReasoningAnimation } from "@/components/v3/ReasoningAnimation";
import { LayersAnimation } from "@/components/v3/LayersAnimation";
import { AttackAnimation } from "@/components/v3/AttackAnimation";

export const metadata = {
  title: "ShipLock: security monitoring that opens the pull request",
  description:
    "Connect GitHub. ShipLock checks supported application paths, shows its evidence and unknowns, and can prepare a mechanical fix for you to approve.",
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
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <span className="v3-mark"><LockMark size={20} /> ShipLock</span>
            <div className="v3-nav-links">
              <a href="#how">How it works</a>
              <Link href="/coverage">What it covers</Link>
              <Link href="/auth">Sign in</Link>
              <Link href="/onboarding" className="v3-btn v3-btn-sm v3-ondark">Get started</Link>
            </div>
          </nav>

          <div className="v3-grid-2" style={{ gap: 48, alignItems: "center", padding: "68px 0 78px" }}>
            <div>
              <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>
                Application security · starts with GitHub
              </p>
              <h1 className="v3-serif" style={{ fontSize: 44, lineHeight: 1.12, margin: "16px 0 20px" }}>
                Security monitoring that opens the pull request.
              </h1>
              <p style={{ fontSize: 17.5, color: "var(--muted-navy)", maxWidth: 560 }}>
                Connect GitHub. ShipLock inventories your stack, checks supported paths from route
                to data, and can prepare a mechanical fix for you to approve. It shows what it could
                not verify. Connect the rest of your stack only when you want its live configuration
                checked too.
              </p>
              <div className="v3-row" style={{ marginTop: 30 }}>
                <Link href="/onboarding" className="v3-btn v3-primary">
                  Get started <ArrowRight size={15} />
                </Link>
                <span className="v3-mono" style={{ fontSize: 12.5, color: "var(--muted-navy)" }}>
                  Free while in preview · repository reads only until you approve a fix
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
          <h2 className="v3-serif">Three steps, then it rechecks supported changes.</h2>
        </div>
        <div className="v3-argument">
          {[
            {
              n: "01",
              h: "It reads the repository",
              b: "Supported Next.js route handlers, schema definitions, imports and deployment clues. Your code names likely auth, database and hosting providers, so ShipLock can inventory the stack without asking you to describe it.",
            },
            {
              n: "02",
              h: "It works out what an attacker reaches",
              b: "For supported route shapes, it follows the guard: who can call this, what identity is resolved, and what narrows the result to that tenant. Findings retain the path and coverage gaps, not just a line number.",
            },
            {
              n: "03",
              h: "It opens the pull request",
              b: "For an allowlisted mechanical fix, it prepares a separate branch and pull request for your review. ShipLock never merges or deploys it. Where the answer is a product decision, it says so instead of guessing.",
            },
          ].map((c) => (
            <div key={c.n}>
              <p className="v3-eyebrow">{c.n}</p>
              <h3>{c.h}</h3>
              <p className="v3-sub" style={{ fontSize: 14 }}>{c.b}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── what it is for ───────────────────────────────────────────────── */}
      <div style={{ background: "var(--paper)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div className="v3-shell v3-section">
          <div className="v3-grid-2" style={{ gap: 48, alignItems: "start" }}>
            <div>
              <p className="v3-eyebrow">Who it is for</p>
              <h2 className="v3-serif" style={{ fontSize: 27, margin: "11px 0 14px" }}>
                Startups with customers and no security hire.
              </h2>
              <p className="v3-sub" style={{ fontSize: 15 }}>
                Small teams shipping quickly, where most of the code was written with an AI assistant
                and nobody has time to audit it by hand. Supabase and Postgres today; other databases
                after that.
              </p>
            </div>
            <div className="v3-card v3-card-p">
              <p className="v3-eyebrow">What you get</p>
              <div style={{ display: "flex", flexDirection: "column", gap: 11, marginTop: 14 }}>
                {[
                  "Paths that reach customer data, ranked by what they reach",
                  "A pull request for the ones with a mechanical fix",
                  "The reasoning behind every finding, with the file it came from",
                  "A record of what each audit did not cover",
                  "Rechecks on supported pull-request changes",
                ].map((line) => (
                  <div key={line} className="v3-row" style={{ gap: 10, flexWrap: "nowrap", alignItems: "flex-start" }}>
                    <Check size={15} style={{ color: "var(--ok)", marginTop: 3 }} />
                    <span style={{ fontSize: 14.5 }}>{line}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>



      {/* ── what it actually does ────────────────────────────────────────── */}
      <div style={{ background: "var(--sand)", borderTop: "1px solid var(--line)", borderBottom: "1px solid var(--line)" }}>
        <div className="v3-shell v3-section">
          <div className="v3-section-hd">
            <p className="v3-eyebrow">What it actually does</p>
            <h2 className="v3-serif">Two levels: infer from code, then deepen with evidence.</h2>
            <p className="v3-sub" style={{ marginTop: 10, maxWidth: 640 }}>
              The repository audit works first and marks what it could not read. Optional provider
              connections can corroborate live configuration. Safe reproduction is the next proof
              level and is not enabled in the preview today.
            </p>
          </div>

          <div className="v3-grid-2" style={{ gap: 40, alignItems: "start" }}>
            <div>
              <h3 style={{ fontSize: 16, fontWeight: 500, marginBottom: 4 }}>
                1 · It joins the supported layers it can read
              </h3>
              <p className="v3-sub" style={{ fontSize: 14, marginBottom: 18 }}>
                One connection. None of these layers is a finding on its own. The join is.
              </p>
              <LayersAnimation />
            </div>

            <div>
              <h3 style={{ fontSize: 16, fontWeight: 500, marginBottom: 4 }}>
                2 · In development: reproduce safely on a copy
              </h3>
              <p className="v3-sub" style={{ fontSize: 14, marginBottom: 18 }}>
                The planned proof runner uses a disposable replica, synthetic tenants and none of
                your production data. This workflow is shown here as the target, not a shipped claim.
              </p>
              <AttackAnimation />
            </div>
          </div>
        </div>
      </div>

      {/* ── evidence ─────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" id="evidence">
        <div className="v3-section-hd">
          <p className="v3-eyebrow">Why this class of bug, and not another</p>
          <h2 className="v3-serif">The failures we look for have already happened.</h2>
          <p className="v3-sub" style={{ marginTop: 10, maxWidth: 640 }}>
            Every one of these is documented and linked. We are not describing a threat model we
            invented. We are describing what has repeatedly gone wrong in applications built the
            way yours was.
          </p>
        </div>

        <div className="v3-grid-3" style={{ gap: 16 }}>
          {[
            {
              tag: "CVE-2025-48757",
              source: "NVD",
              href: "https://nvd.nist.gov/vuln/detail/CVE-2025-48757",
              head: "170+ live apps, one missing row policy",
              body:
                "Applications generated by an AI builder shipped with row-level security absent on tables holding user records. Anyone with the public key could read every row. This is the exact shape of the first path our reasoner looks for.",
            },
            {
              tag: "Mythos IDOR benchmark",
              source: "Semgrep",
              href: "https://semgrep.dev/blog/2026/mythos-idor-benchmark/",
              head: "Broken object-level access is still the hardest to catch",
              body:
                "A benchmark built specifically because ownership bugs resist pattern matching: the code looks correct in isolation and is only wrong relative to who is calling. It is why we reason over routes and schema together rather than grepping for a rule.",
            },
            {
              tag: "OWASP Top 10:2025",
              source: "OWASP",
              href: "https://owasp.org/Top10/",
              head: "Broken access control, still number one",
              body:
                "The category has led the list across consecutive revisions, and it is the one a scanner is worst at, because the rule it breaks is specific to your product rather than to a language.",
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
          More, with the reasoning written out: <Link href="/incidents">real incidents</Link> and{" "}
          <Link href="/owasp">how the OWASP categories map to what we check</Link>.
        </p>
      </div>

      {/* ── close ────────────────────────────────────────────────────────── */}
      <div className="v3-shell v3-section" style={{ textAlign: "center" }}>
        <h2 className="v3-serif" style={{ fontSize: 30, marginBottom: 12 }}>
          Point it at a repository.
        </h2>
        <p className="v3-sub" style={{ maxWidth: 480, margin: "0 auto 26px" }}>
          The first audit shows what ShipLock found, the evidence behind it, and what remains unread.
        </p>
        <Link href="/onboarding" className="v3-btn v3-primary">
          Get started <ArrowRight size={15} />
        </Link>
      </div>

      <div className="v3-band">
        <div className="v3-shell" style={{ padding: "26px 0", fontSize: 13, color: "var(--muted-navy)" }}>
          <div className="v3-between">
            <span className="v3-row" style={{ gap: 8 }}><LockMark size={15} /> ShipLock</span>
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
