import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Real, product-accurate Privacy Policy — describes what this codebase
// actually collects/stores/sends, not generic boilerplate. Drafted from the
// real data flows (security.md's "hash, never store raw" rules, lib/crypto.ts
// encryption, the third-party services actually wired in). NOT a substitute
// for real legal review before this handles real paying customers' PII —
// see the plan / conversation this was built from for that caveat.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Privacy policy",
  description:
    "What we collect, why, and how it's protected — hashed project references, AES-256-GCM encrypted keys, and the third parties we actually use.",
};


export default function PrivacyPage() {
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
              <Link href="/terms">Terms</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>
          <header className="dxd-hero" style={{ gridTemplateColumns: "1fr" }}>
            <div>
              <p className="dxd-eyebrow">Legal</p>
              <h1 className="dxd-display" style={{ fontSize: "clamp(30px,4.5vw,44px)" }}>
                Privacy Policy
              </h1>
              <p className="dxd-lede">Last updated 2026-07-27.</p>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        <section className="dxd-section" style={{ maxWidth: 720 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 28, fontSize: 15, lineHeight: 1.75 }}>
            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What we collect</h2>
              <p>
                <b>Account:</b> your email address, and, if you sign in with Google or GitHub,
                the basic profile information those providers share (name, email, avatar).
              </p>
              <p>
                <b>Your project, to scan it:</b> the Supabase project URL and anon (public) key
                you paste in. Your scan history stores only a one-way SHA-256 hash of the
                project URL, so we can recognize repeat scans without keeping the real address
                in that record. For continuous monitoring — which starts with your first scan —
                we additionally keep the project URL you&apos;ve asked us to watch (a re-scan
                needs a real address, not a hash) and your anon key encrypted at rest
                (AES-256-GCM); the key is decrypted only in memory, at scan time, and never
                logged. We never retain a service-role key: if you paste one by mistake, we
                flag it as a critical finding and don&apos;t store it.
              </p>
              <p>
                <b>Scan results:</b> the findings and fixes from every audit we run, tied
                to your account, so your dashboard can show your history.
              </p>
              <p>
                <b>Optional connections:</b> if you connect GitHub, we read your repository
                contents to scan for committed secrets and vulnerable dependencies, and can open
                fix pull requests to a new branch for you to review and merge — we never push to
                your default branch and never apply changes to your production database. If you
                connect your coding agent, we issue a personal access token (stored only as a
                hash) that the ShipLock tool on your own machine uses to read your findings. If
                you turn on a public Verified report, the posture summary at its link becomes
                shareable — counts and coverage only, never your specific findings — and it stays
                off until you enable it.
              </p>
              <p>
                <b>Billing:</b> Stripe handles your card details directly — we never see or store
                your card number. We keep your Stripe customer and subscription IDs so we know
                who&apos;s paid.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What we don&apos;t collect</h2>
              <p>
                We never ask for your Supabase service_role key or database password. Any GitHub
                access is optional, granted by you, and used only to scan your source and open fix
                PRs you review. Scanning uses only the same public anon key your app&apos;s own frontend
                already exposes to every visitor. We don&apos;t read the contents of your
                database tables — a scan checks configuration (is a table protected, is a key
                exposed, does an endpoint answer without authentication), not your users&apos;
                data.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>
                Who we share it with — our sub-processors
              </h2>
              <p>
                These are every third party that processes data on our behalf, what they handle,
                and why. We don&apos;t sell data to anyone, ever. If we add or replace one, we
                update this list before the change takes effect.
              </p>
              <div style={{ overflowX: "auto", margin: "14px 0" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 460 }}>
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--d-line)" }}>
                      <th style={{ padding: "8px 10px 8px 0" }}>Provider</th>
                      <th style={{ padding: "8px 10px 8px 0" }}>What it handles</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      ["Supabase", "Our own database and authentication — your account record, scan history, and monitoring settings."],
                      ["Vercel", "Hosting for the ShipLock application itself."],
                      ["Stripe", "Billing and subscription management. Card details go to Stripe directly; we never see them."],
                      ["Resend", "Transactional email — alerts and receipts. Receives your email address."],
                      ["PostHog", "Product analytics on how the app is used. Not your scan data."],
                      ["Anthropic", "Turns raw check results into plain-English findings and fixes. This payload never contains your anon key or any row of your data, by construction."],
                      ["GitHub", "Only if you connect it: source scanning and fix pull requests."],
                    ].map(([name, what]) => (
                      <tr key={name} style={{ borderBottom: "1px solid var(--d-line)" }}>
                        <td style={{ padding: "10px 10px 10px 0", fontWeight: 600, whiteSpace: "nowrap" }}>{name}</td>
                        <td style={{ padding: "10px 10px 10px 0", color: "var(--d-muted)", lineHeight: 1.6 }}>{what}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                Monitoring runs never call Anthropic at all — findings from a scheduled re-check
                are worked out deterministically from the raw result, so no scan data leaves our
                own systems on those passes.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Your rights over your data</h2>
              <p>
                You can ask us for a copy of what we hold about you, ask us to correct it, or ask
                us to delete it — email{" "}
                <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> and we&apos;ll
                action it. Deleting your account removes your scan history, the monitored project
                URL, and your encrypted anon key. You can stop monitoring at any time by
                disconnecting the project or cancelling, and you can revoke coding-agent tokens
                and turn off the Verified report from your dashboard whenever you like.
              </p>
              <p>
                If your use of ShipLock means we process personal data on your behalf and you need
                a data processing agreement, email us and we&apos;ll put one in place.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Retention and deletion</h2>
              <p>
                We keep scan history so your dashboard can show trends over time. To delete your
                account and everything tied to it, email{" "}
                <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> — this is a manual
                process today; a self-serve delete is on our roadmap.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Questions</h2>
              <p>
                <a href="mailto:support@shiplock.dev">support@shiplock.dev</a>
              </p>
            </div>
          </div>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
          </span>
          <span>
            <Link href="/">Home</Link> · <Link href="/terms">Terms</Link>
          </span>
        </footer>
      </div>
    </main>
  );
}
