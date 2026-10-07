import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage } from "@/components/v3/LegalPage";

// Q28: preview terms written from what the product does today. A working
// draft, not legal advice; have it reviewed before paid launch.
export const metadata: Metadata = {
  title: "Terms of service",
  description: "Plain terms: what you authorize, what ShipLock does and does not do, and what a result means.",
};

export default function TermsPage() {
  return (
    <LegalPage title="Terms of service" updated="2026-10-07" other={{ href: "/privacy", label: "Privacy" }}>
      <section>
        <h2>Plans and pricing</h2>
        <p>
          ShipLock is in preview. There is a Free plan and a Pro plan is planned; billing is off and nothing is charged
          today. Before any charge, the price, renewal, included usage, cancellation and refund terms are shown and
          you choose to buy. Preview access never authorizes a later charge.
        </p>
      </section>

      <section>
        <h2>What you authorize</h2>
        <p>
          By installing the GitHub App and selecting repositories, you authorize ShipLock to read them to audit them. By
          connecting a database, you authorize read-only access to its configuration. By adding the traffic snippet,
          you authorize it to report request metadata from your application. You confirm you own these, or are
          authorized by whoever does. You can withdraw any of it at any time by disconnecting, uninstalling, or deleting
          your account.
        </p>
        <p>
          A proof runs only after you authorize that specific test, only on a disposable copy of your schema with made
          up data, and never against your production systems or anyone else&apos;s.
        </p>
      </section>

      <section>
        <h2>What ShipLock does, and does not do</h2>
        <ul>
          <li>It reads code, configuration and metadata. It never reads the rows in your tables.</li>
          <li>
            It attacks your application safely to find vulnerabilities: your own AI proposes attacks and must prove each
            one with quoted lines from your code, and any replay runs on a disposable copy with made up data. ShipLock
            never sends attack traffic to your production application, or to anyone else&apos;s.
          </li>
          <li>
            A candidate is not a confirmed issue. Only an issue backed by proof, a connected service or observed traffic
            sets your status; the rest is shown to review.
          </li>
          <li>It can prepare a pull request for you to review. It opens one only when you click, the change runs through your own CI like any other, and ShipLock never merges or deploys.</li>
          <li>It never changes your provider settings or blocks your traffic. A rate limit or firewall rule reaches your stack only through a pull request you approve.</li>
          <li>AI reasoning runs on your own AI, under your provider&apos;s terms and your account&apos;s limits.</li>
        </ul>
      </section>

      <section>
        <h2>What a result means</h2>
        <p>
          ShipLock reports what it read, what it found, what it reproduced, and what it could not read. It is not a
          penetration test or a certification. No automated tool finds everything: business logic, chained flaws and
          issues that only appear at runtime can be missed. A result with nothing open does not mean your application is
          secure. You decide whether and how to apply any change.
        </p>
        <p>
          A shareable report states what ShipLock monitors and when it last ran. It is not a security certification,
          audit opinion or compliance attestation; do not present it as one.
        </p>
      </section>

      <section>
        <h2>Warranties and liability</h2>
        <p>
          The service is provided as is. To the extent the law allows, we disclaim implied warranties of
          merchantability and fitness for a particular purpose, and we do not warrant that it is uninterrupted, error
          free, or that it finds every issue.
        </p>
        <p>
          Our total liability for any claim connected to ShipLock is limited to what you paid us in the twelve months
          before the claim. We are not liable for indirect, incidental, special or consequential damages, or for lost
          profits, revenue, data or goodwill, including from an issue we did not catch or a change you applied. Nothing
          here limits liability that cannot lawfully be limited, including for fraud, gross negligence or wilful
          misconduct. If you are a consumer, your statutory rights are unaffected.
        </p>
      </section>

      <section>
        <h2>Your account and data</h2>
        <p>
          Keep your sign-in secure and do not connect anything you are not authorized to have checked. What we collect
          and who processes it is in the <Link href="/privacy">privacy policy</Link>. If you need a data processing
          agreement, email <a href="mailto:support@shiplock.dev">support@shiplock.dev</a>.
        </p>
      </section>

      <section>
        <h2>Changes</h2>
        <p>We may update these terms as the product changes, and we change the date at the top when we do.</p>
      </section>
    </LegalPage>
  );
}
