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
              <p className="dxd-lede">Last updated 2026-07-11.</p>
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
                <b>Scan results:</b> the grade, findings, and fixes from every audit we run, tied
                to your account, so your dashboard can show your history.
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
                We never ask for your Supabase service_role key, database password, or repository
                access. Scanning uses only the same public anon key your app&apos;s own frontend
                already exposes to every visitor. We don&apos;t read the contents of your
                database tables — a scan checks configuration (is a table protected, is a key
                exposed, does an endpoint answer without authentication), not your users&apos;
                data.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Who we share it with</h2>
              <p>
                <b>Stripe</b> — billing and subscription management.{" "}
                <b>Resend</b> — transactional email (alerts, receipts).{" "}
                <b>PostHog</b> — product analytics on how the app itself is used, not your scan
                data. <b>Anthropic</b> — your scan&apos;s raw check results are sent to power the
                plain-English grade and fixes; this payload never contains your anon key or any
                row of your data, by construction. We don&apos;t sell data to anyone, ever.
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
