import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Real, product-accurate Terms of Service — matches what's actually built
// (self-serve cancellation via /api/portal + the dashboard Billing button)
// rather than promising features that don't exist.
//
// Revised 2026-07-27 for the prepaid 6/12-month terms and to close four gaps a
// research pass surfaced. NOT legal advice and NOT a substitute for review by a
// qualified lawyer before this handles real money — the clauses below are
// drafted to be a sound starting point for that review, not a replacement:
//
//  1. AUTHORISATION TO SCAN. We point automated requests at a customer's live
//     infrastructure. Documented, explicit customer authorisation is what
//     separates that from unauthorised access under the CFAA, and the customer
//     must actually have authority to grant it (their Supabase project, their
//     app). Previously implied, now explicit.
//  2. LIMITATION OF LIABILITY + WARRANTY DISCLAIMER. There was no cap at all.
//     Standard SaaS practice is a cap tied to fees paid, with carve-outs for
//     gross negligence and wilful misconduct (which are commonly unenforceable
//     to disclaim anyway).
//  3. THE VERIFIED REPORT. It is published for third parties to read, which is
//     exactly the fact pattern for a negligent-misrepresentation claim by
//     someone who relied on it. It now states what it does and does not
//     attest, and disclaims third-party reliance.
//  4. CONSUMER WITHDRAWAL RIGHTS. CJEU C-234/25 (Sky Österreich, 9 July 2026)
//     classifies a subscription to a dynamic service as a "digital service",
//     which is NOT in the CRD's list of withdrawal-right exceptions — so an EU
//     consumer cannot waive the 14-day withdrawal right, and a prepaid annual
//     term must honour it (pro-rata for use). Also note the FTC's
//     click-to-cancel rule was vacated by the Eighth Circuit in July 2025 and
//     is being re-proposed; ROSCA still applies regardless, which is a further
//     reason the prepaid terms deliberately do not auto-renew.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Terms of service",
  description:
    "Plain-language terms: $49/month or a prepaid 6- or 12-month term, 7-day free trial, self-serve cancellation, what the audit covers and what it can't promise.",
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
              <p className="dxd-lede">Last updated 2026-07-27.</p>
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
                One product, three ways to pay for it, all billed by Stripe. Nothing is held back
                on the cheaper terms, a longer term is simply less money.
              </p>
              <ul style={{ paddingLeft: 20, display: "grid", gap: 6, margin: "12px 0" }}>
                <li>
                  <b>$49/month</b>, a recurring subscription. New subscriptions include 7 days
                  free; you aren&apos;t charged until the trial ends, and cancelling during the
                  trial costs nothing. After the trial it renews monthly until you cancel.
                </li>
                <li>
                  <b>$265 for six months</b> and <b>$470 for twelve months</b>, a single charge
                  that buys a fixed window of access. <b>These do not auto-renew.</b> When the
                  window ends, access simply stops until you choose to buy another.
                </li>
              </ul>
              <p>
                <b>Cancelling the monthly plan:</b> self-serve, any time, open <b>Billing</b>{" "}
                from your dashboard to manage or cancel through Stripe&apos;s billing portal (or
                email <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> and
                we&apos;ll do it for you). You keep access through the end of the period
                you&apos;ve already paid for; we don&apos;t offer partial-month refunds.
              </p>
              <p>
                <b>Prepaid terms carry no cancellation fee</b>, because there is nothing to
                cancel, you bought a window, not a commitment. We don&apos;t charge an early
                termination fee under any plan, ever.
              </p>
              <p>
                <b>Refunds and withdrawal.</b> If you&apos;re a consumer in the EU, UK, or
                another jurisdiction with a statutory cooling-off period, you keep that right and
                nothing here waives it: you may withdraw within 14 days of purchase, and
                we&apos;ll refund what you paid, less a proportionate amount for the period you
                actually had access. Outside that, prepaid terms are non-refundable, but if a
                prepaid term isn&apos;t working out for you, email us. We&apos;d rather refund
                you than keep money you feel you shouldn&apos;t have spent.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>
                Your authorisation to scan
              </h2>
              <p>
                ShipLock works by sending automated requests to infrastructure you tell us is
                yours. By connecting a project you are giving us <b>express permission</b> to do
                that, and you confirm that you own the database and application URL you
                submit, or are authorised by whoever does to have them scanned. Please
                don&apos;t submit anything you don&apos;t have that authority over.
              </p>
              <p>
                Our checks are read-only and non-destructive. We look at how your project is
                configured and what it will answer to an anonymous request. We do not attempt to
                exploit, damage, degrade, or persist in anything we find, and we do not attempt
                to access other customers&apos; data. You can revoke this permission at any time
                by disconnecting the project or cancelling.
              </p>
              <p>
                Your infrastructure providers have their own acceptable-use terms governing
                security testing. Our checks are designed to stay within ordinary, documented
                API use of the public endpoints your app already exposes, but you remain
                responsible for your relationship with your own providers.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What you get</h2>
              <p>
                A 16-check audit of your connected database and application and, while your
                subscription is active, the fix for every finding, delivered as a reviewable
                pull request or handed to your coding agent. Continuous monitoring is genuinely
                live for the pieces we say are live: a re-scan on every pull request, an hourly
                lightweight critical-check pass, and a full deep scan every 48 hours. GitHub
                source scanning and the coding-agent integration activate when you connect them;
                anything we haven&apos;t shipped yet is labeled
                &ldquo;coming soon&rdquo; in the product itself, and we won&apos;t bill you
                differently based on roadmap features landing.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>What ShipLock is, and isn&apos;t</h2>
              <p>
                ShipLock identifies configuration issues in your project using automated checks
                against your application&apos;s public surface and, where you have connected one,
                read-only access to your database. It is not a penetration
                test, not a guarantee that your application is free of vulnerabilities, and not a
                substitute for a professional security review where the stakes call for one. We
                do not attempt to exploit anything we find. You&apos;re responsible for reviewing
                and applying the fixes we surface.
              </p>
              <p>
                No security tool finds everything, and we say so throughout the product rather
                than in the fine print. Business logic, chained flaws, runtime-only issues, and
                anything requiring human judgement are outside what automated checking can reach.
                A clean ShipLock result means the checks we run found nothing, it does not mean
                your application is secure.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>
                Warranties and liability
              </h2>
              <p>
                We take this seriously and we run ShipLock against our own infrastructure before
                yours. But the service is provided <b>&ldquo;as is&rdquo;</b>, and to the extent
                the law allows we disclaim implied warranties of merchantability and fitness for
                a particular purpose. We don&apos;t warrant that the service will be
                uninterrupted or error-free, or that it will identify every issue in your
                application.
              </p>
              <p>
                <b>Our total liability</b> to you for any claim connected to ShipLock is limited
                to the amount you paid us in the twelve months before the claim arose. We
                aren&apos;t liable for indirect, incidental, special, or consequential damages,
                or for lost profits, revenue, data, or goodwill, including damages arising from
                a vulnerability we didn&apos;t catch, a fix applied incorrectly, or downtime
                caused by a change you made on our recommendation.
              </p>
              <p>
                None of the above limits liability for our own gross negligence, wilful
                misconduct, fraud, death or personal injury, or anything else that can&apos;t
                lawfully be limited. If you&apos;re a consumer, your statutory rights are
                unaffected by anything in this section.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>
                The Verified report
              </h2>
              <p>
                You can publish a Verified report and badge showing that your project is under
                continuous monitoring. It&apos;s off until you turn it on, and you control it.
              </p>
              <p>
                <b>What it attests:</b> that a project was connected to ShipLock, which checks we
                run, and when we last ran them. <b>What it does not attest:</b> that your
                application is secure, that it is free of vulnerabilities, or that it meets any
                particular standard, certification, or regulatory requirement. It is a statement
                about monitoring, not a certification, and it never displays your findings.
              </p>
              <p>
                The report is provided for information only. We aren&apos;t liable to you or to
                any third party who reads it for decisions taken in reliance on it, and you
                agree not to present it as a security certification, audit opinion, or
                compliance attestation. Please don&apos;t display it for a project we&apos;re not
                actually monitoring, if monitoring stops, the report says so, and you should
                take the badge down.
              </p>
            </div>

            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>
                Your data, and your customers&apos; data
              </h2>
              <p>
                What we collect and why is set out in our{" "}
                <Link href="/privacy">Privacy Policy</Link>, including the third parties that
                process data on our behalf. In the ordinary course we don&apos;t process your end
                users&apos; personal data, our checks look at configuration and at whether
                endpoints answer, not at the contents of your tables.
              </p>
              <p>
                If your use of ShipLock does involve us processing personal data on your behalf
                and you need a data processing agreement, email{" "}
                <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> and we&apos;ll put
                one in place.
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
