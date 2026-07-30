import type { Metadata } from "next";
import Link from "next/link";
import { Reveal, RevealList } from "@/components/d/bits";
import { LockMark } from "@/components/d/Brand";

// What the engagement actually covers, stated at the level of detail a technical
// founder needs to evaluate it.
//
// VOICE (PRODUCT-DESIGN §13): this reader is a competent engineer who has not had
// time to own security. They are deciding whether to trust us with their
// company's data, and the thing that earns that is precision — naming the
// mechanism, the boundary and the limit — not reassurance. So: intermediate
// jargon (RLS, JWT claims, SSRF, supply chain) without a glossary, no persuasion,
// no urgency, and every limit stated where the capability is claimed rather than
// in a footnote.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Scope of engagement",
  description:
    "The four areas ShipLock covers — continuous configuration and code review, sandboxed exploitation, traffic defence, and verified remediation — with the boundaries of each stated plainly.",
};

const AREAS = [
  {
    id: "01",
    name: "Continuous review",
    lead: "Your Postgres configuration, application source and live surface, re-examined on every pull request and on a fixed schedule.",
    detail: [
      "Row-level security posture per table, policy expressions that resolve to unconditional access, column-level grants held by browser-reachable roles, and the full set of Supabase advisor lints ingested rather than duplicated.",
      "Source analysis for committed and historical credentials, dependency advisories matched against your lockfile, injection and XSS sinks, and the stack-specific failure of a service-role client reachable from a client component.",
      "The deployed artefact itself: what your bundle ships, whether source maps are public, DNS authentication records, and whether your edge protection can be reached around.",
    ],
    limit:
      "Static analysis reasons about code as written. Where a filter is applied somewhere our import graph cannot follow, we say the finding is inference and label it as such.",
  },
  {
    id: "02",
    name: "Sandboxed exploitation",
    lead: "We reconstruct the component under test in an isolated environment and attack it — never your production system.",
    detail: [
      "A throwaway arena is provisioned: either an ephemeral branch of your project carrying schema and policies but no data, or the specific table and its policies rebuilt on our own infrastructure. Two synthetic tenants are seeded into it.",
      "Authenticated as the first tenant, we attempt to read the second's rows. A control query runs first — if the arena cannot return the caller's own row, the run is discarded rather than reported as clean.",
      "Where the deterministic probe finds nothing, a reasoning agent proposes further queries. Its action space is constrained by a deterministic guard to read-only statements inside the disposable schema; every proposal, including refused ones, is recorded.",
    ],
    limit:
      "We do not attack your production application, and we do not run an adversarial agent against anything you operate. Policies that depend on other tables or custom functions cannot be reconstructed faithfully, and we decline to test those rather than report an unreliable result.",
  },
  {
    id: "03",
    name: "Traffic defence",
    lead: "Application-layer abuse identified from your authentication events, and optionally turned away in the request.",
    detail: [
      "Credential stuffing distinguished by spread across accounts, brute force by concentration, and account takeover by the sequence of failures, success and password change from one source.",
      "Distributed floods assessed against your own traffic baseline rather than a fixed rate, and separated from legitimate growth by whether the surge is concentrated on one endpoint.",
      "Detection requires no installation — it reads the authentication log your database already writes. An optional edge module upgrades detection to enforcement, turning requests away before they reach your application.",
    ],
    limit:
      "Volumetric network-layer attacks are absorbed by your hosting provider's network, not by us; that is a function of capacity and position, and we do not claim it. Automatic response is limited to rate-limiting a single endpoint, is reversible, and lifts itself.",
  },
  {
    id: "04",
    name: "Verified remediation",
    lead: "Mechanical fixes are applied as a diff against your code. Everything requiring judgement is prepared, not performed.",
    detail: [
      "Where the correct output is determined entirely by the input — response headers, a build flag, a variable that should not carry a public prefix, workflow permissions — we open a pull request containing the edited file.",
      "Database changes are demonstrated before they are offered: the fix is applied in the arena, the attack re-run to confirm it now fails, and legitimate access re-run to confirm it still succeeds. A change that closes the attack by denying everyone is rejected.",
      "Findings close on evidence. When a subsequent pass no longer reproduces the condition, the finding is archived automatically rather than waiting for anyone to mark it done.",
    ],
    limit:
      "Application logic is never machine-authored. Authorisation rules, injection fixes and ownership checks arrive as a draft pull request for you or your coding agent to complete. A leaked credential is a rotation, and no pull request is offered for it.",
  },
] as const;

export default function CoveragePage() {
  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/" className="dxd-wordmark">
              <span className="dxd-wordmark-lock"><LockMark size={19} /></span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <Link href="/owasp">OWASP</Link>
              <Link href="/incidents">Incidents</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-paper">Sign in</Link>
            </div>
          </nav>

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">Scope of engagement</p>
            <h1 className="dxd-statement">Four areas, and the edge of each.</h1>
            <p className="dxd-lede" style={{ margin: "18px 0 0", maxWidth: "62ch" }}>
              What follows is the whole of what we do, including where each capability stops.
              A security engagement whose limits are unstated is not one you can plan around.
            </p>
          </header>
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body">
        <RevealList>
          {AREAS.map((area) => (
            <section key={area.id} style={{ marginBottom: 52 }} aria-label={area.name}>
              <div style={{ display: "flex", gap: 14, alignItems: "baseline" }}>
                <span className="dxd-mono" style={{ fontSize: 12, color: "var(--d-bronze)" }}>{area.id}</span>
                <h2 className="dxd-serif" style={{ margin: 0, fontSize: 23 }}>{area.name}</h2>
              </div>

              <p className="dxd-lede" style={{ margin: "12px 0 18px", maxWidth: "64ch" }}>{area.lead}</p>

              <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 12 }}>
                {area.detail.map((line) => (
                  <li key={line} style={{ fontSize: 14.5, lineHeight: 1.75, color: "var(--d-muted)", maxWidth: "70ch" }}>
                    {line}
                  </li>
                ))}
              </ul>

              <div className="dxd-surface" style={{ marginTop: 18, padding: 14, maxWidth: "70ch" }}>
                <p className="dxd-mono" style={{ margin: "0 0 6px", fontSize: 11, color: "var(--d-bronze)" }}>
                  BOUNDARY
                </p>
                <p style={{ margin: 0, fontSize: 14, lineHeight: 1.75, color: "var(--d-muted)" }}>{area.limit}</p>
              </div>
            </section>
          ))}
        </RevealList>

        <Reveal>
          <section aria-label="Engagement terms" style={{ marginTop: 8 }}>
            <h2 className="dxd-serif" style={{ fontSize: 20, marginBottom: 10 }}>Terms of the engagement</h2>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)", maxWidth: "70ch" }}>
              $49 per month, billed monthly, with the first seven days free. Cancellation is
              self-serve from your dashboard and takes effect at the end of the current period —
              there is no cancellation fee, no notice period, and no requirement to contact us.
              Prepaid six- and twelve-month terms are one-time charges rather than auto-renewing
              subscriptions, and carry no early-termination fee.
            </p>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)", maxWidth: "70ch", marginTop: 12 }}>
              Autonomous action is off by default and governed by a per-account switch you control.
              With it off, we observe and report; nothing is changed on your systems without you.
              Full terms are on the <Link href="/terms">terms page</Link>, and what we store is
              described on the <Link href="/privacy">privacy page</Link>.
            </p>
          </section>
        </Reveal>
      </div>
    </main>
  );
}
