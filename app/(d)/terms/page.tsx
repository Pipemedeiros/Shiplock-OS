import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Real, product-accurate Terms of Service — matches what's actually built
// (self-serve cancellation via /api/portal + the dashboard Billing button)
// rather than promising features that don't exist. NOT a substitute for
// real legal review before this handles real paying customers — see the
// plan / conversation this was built from for that caveat.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Terms of service",
  description:
    "Plain-language terms: $49/month, 7-day free trial, self-serve cancellation, what the audit covers and what it can't promise.",
};


export default function TermsPage() {
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
              <Link href="/privacy">Privacy</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-ghost">
                Sign in
              </Link>
            </div>
          </nav>
          <header className="dxd-hero" style={{ gridTemplateColumns: "1fr" }}>
            <div>
              <p className="dxd-eyebrow">Legal</p>
              <h1 className="dxd-display" style={{ fontSize: "clamp(30px,4.5vw,44px)" }}>
                Terms of Service
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
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>The subscription</h2>
              <p>
                ShipLock is $49/month, billed by Stripe. New subscriptions include 7 days free —
                you won&apos;t be charged until the trial ends, and you can cancel during the
                trial at no cost. After the trial, billing renews monthly until cancelled.
              </p>
              <p>
                <b>Cancelling:</b> self-serve, any time — open <b>Billing</b> from your
                dashboard to manage or cancel your subscription through Stripe&apos;s billing
                portal (or email{" "}
                <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> and we&apos;ll do
                it for you). You keep access through the end of the period you&apos;ve already
                paid for; we don&apos;t offer partial-month refunds.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What you get</h2>
              <p>
                A 16-check audit of your connected Supabase project, a grade, and — while your
                subscription is active — the fix and a copy-paste AI-agent prompt for every
                finding. Continuous monitoring is genuinely live for the pieces we say are live:
                deploy-triggered re-scans, an hourly lightweight critical-check pass, and a full
                deep scan every 48 hours. Anything we haven&apos;t shipped yet — GitHub source
                scanning, Vercel environment audits, the Cloudflare edge layer — is labeled
                &ldquo;coming soon&rdquo; in the product itself, and we won&apos;t bill you
                differently based on roadmap features landing.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What ShipLock is — and isn&apos;t</h2>
              <p>
                ShipLock identifies configuration issues in your project using automated checks
                against your Supabase project&apos;s public API surface. It is not a penetration
                test, not a guarantee that your application is free of vulnerabilities, and not a
                substitute for a professional security review where the stakes call for one. We
                do not attempt to exploit anything we find — see our methodology for what that
                means in practice. You&apos;re responsible for reviewing and applying the fixes
                we surface; we&apos;re not liable for damages arising from a vulnerability we
                didn&apos;t catch, a fix that was applied incorrectly, or downtime caused by a
                change you made based on our recommendations.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Your account</h2>
              <p>
                You&apos;re responsible for keeping your login credentials secure and for the
                accuracy of the Supabase URL and anon key you provide us. Don&apos;t submit
                credentials or projects you don&apos;t have the right to have scanned.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Changes</h2>
              <p>
                We may update these terms as the product changes. We&apos;ll update the date at
                the top of this page when we do.
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
            <Link href="/">Home</Link> · <Link href="/privacy">Privacy</Link>
          </span>
        </footer>
      </div>
    </main>
  );
}
