import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";

// Product-accurate preview terms. These are a working draft, not legal advice;
// obtain qualified review before charging customers or running active tests.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Terms of service",
  description:
    "Plain-language preview terms: authorization, what ShipLock reads, approval boundaries, and what an audit cannot guarantee.",
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
              <p className="dxd-lede">Last updated 2026-09-19.</p>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell">
        <section className="dxd-section" style={{ maxWidth: 720 }}>
          <div style={{ display: "flex", flexDirection: "column", gap: 28, fontSize: 15, lineHeight: 1.75 }}>
            <div>
              <h2 className="dxd-h2" style={{ fontSize: 22 }}>Preview access and pricing</h2>
              <p>
                ShipLock is free during the current preview. Billing is disabled and we do not
                offer a paid subscription or prepaid term today. Previous prices and trials are
                withdrawn.
              </p>
              <p>
                If pricing is introduced, the price, renewal terms, included usage, cancellation,
                and refund rules will be shown before you make an affirmative purchase. Preview
                access does not authorize ShipLock to charge a stored payment method later.
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
                by disconnecting the project or deleting your account.
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
                A repository audit with findings, inspectable evidence, and explicit coverage of
                what ShipLock could not read. Optional provider connections can add live
                configuration evidence. Where a mechanical remedy is supported, ShipLock may
                prepare a reviewable pull request; it never approves, merges, deploys, or changes
                provider configuration for you. Scheduled coverage is reported from actual run
                state, not promised merely because a collector exists.
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
