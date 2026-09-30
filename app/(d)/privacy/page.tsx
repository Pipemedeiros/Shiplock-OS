import type { Metadata } from "next";
import Link from "next/link";
import { LegalPage } from "@/components/v3/LegalPage";

// Q28: written from the code paths that exist today (GitHub App archive read,
// customer AI, traffic snippet fields, proofs on an embedded replica, consent
// gated PostHog, welcome email). A working draft, not legal advice; have it
// reviewed before paid launch.
export const metadata: Metadata = {
  title: "Privacy policy",
  description: "What ShipLock reads, what it keeps, who processes it, and how to get it deleted.",
};

const PROCESSORS: [string, string][] = [
  ["Supabase", "Our database and sign-in: your account, repository list, route facts, findings, and encrypted credentials."],
  ["Vercel", "Hosts ShipLock and runs its audits."],
  ["GitHub", "The GitHub App you install: reading the repositories you select and opening pull requests you click."],
  ["Resend", "Email: the welcome email, and alerts if you turn them on. Receives your email address."],
  ["PostHog", "Product analytics, only after you accept analytics cookies. Never your code or findings."],
  ["Stripe", "Billing, when paid plans open. Card details go to Stripe; we never see them."],
  ["Anthropic", "Only if ShipLock itself pays for an AI run, which is off today. Your own AI runs under your own account with your provider."],
];

export default function PrivacyPage() {
  return (
    <LegalPage title="Privacy policy" updated="2026-09-30" other={{ href: "/terms", label: "Terms" }}>
      <section>
        <h2>What we read</h2>
        <p><b>Your account.</b> Your email address, and the basic profile Google or GitHub shares when you sign in with them.</p>
        <p>
          <b>Your repositories, through the GitHub App.</b> When you install the app and select repositories, we read
          those repositories at a specific commit to audit them: which routes exist, what they check, and which tables
          they reach. We do not keep a copy of your repository. We keep what the audit concluded: route facts, findings
          with file paths, and short quoted lines as evidence.
        </p>
        <p>
          <b>Your database, if you connect it.</b> A read-only connection to Supabase or Postgres lets us read
          configuration: schemas, row policies, grants and buckets. We never read the rows in your tables. Credentials
          are encrypted at rest (AES 256 GCM), decrypted only in memory while a check runs, and never logged.
          Disconnecting deletes them.
        </p>
        <p>
          <b>Your own AI, if you connect it.</b> AI reasoning runs on your own AI: Claude Code, Codex, or an API key you
          save. An API key is encrypted at rest and used only for tasks you approved; the files a task covers go to
          your model provider under your account. With a coding agent, we send the task and file hashes; your agent
          reads the files from your own checkout.
        </p>
        <p>
          <b>Traffic, if you add the traffic snippet.</b>{" "}For each request it reports the path, method, user agent, a
          visitor id the snippet computes, an optional session id, and a timestamp. Never request or response bodies,
          passwords, cookies or your users&apos; data. Where we read Supabase gateway logs instead, client addresses
          are hashed with a daily rotating key on arrival and never kept.
        </p>
        <p>
          <b>Proofs.</b> When you authorize a test, it runs on a disposable copy of your schema filled with made up
          data, never on your production database.
        </p>
      </section>

      <section>
        <h2>Cookies</h2>
        <p>
          Sign-in cookies are always on because the app cannot work without them. Analytics cookies (PostHog) start
          only after you accept them in the cookie banner. If you choose Reject, we remember it and never ask again on
          that browser.
        </p>
      </section>

      <section>
        <h2>Email</h2>
        <p>
          We send one welcome email when you create an account. Security alert emails are off today; when they open,
          they are sent only when something meaningful changes. We never sell or share your address.
        </p>
      </section>

      <section>
        <h2>Who processes data for us</h2>
        <p>Every third party that handles data on our behalf. We do not sell data. If this list changes, we update it here first.</p>
        <table>
          <thead><tr><th>Provider</th><th>What it handles</th></tr></thead>
          <tbody>{PROCESSORS.map(([name, what]) => <tr key={name}><td>{name}</td><td>{what}</td></tr>)}</tbody>
        </table>
      </section>

      <section>
        <h2>Your rights</h2>
        <p>
          Ask us for a copy of what we hold about you, to correct it, or to delete it, at{" "}
          <a href="mailto:support@shiplock.dev">support@shiplock.dev</a>. You can disconnect a database, revoke an AI
          key or agent token, remove the traffic snippet and turn off a shareable report from Settings at any time. If
          you need a data processing agreement, email us and we will put one in place.
        </p>
      </section>

      <section>
        <h2>Retention and deletion</h2>
        <p>
          We keep audit history so your dashboard can show change over time. Traffic events are kept for a limited
          window and then deleted automatically. To delete your account and everything tied to it, email{" "}
          <a href="mailto:support@shiplock.dev">support@shiplock.dev</a>; this is done by hand today. Uninstall the
          GitHub App from GitHub as well.
        </p>
        <p>See also the <Link href="/terms">terms of service</Link>.</p>
      </section>
    </LegalPage>
  );
}
