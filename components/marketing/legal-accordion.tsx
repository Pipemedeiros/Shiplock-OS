type Section = { title: string; body: string };

const TERMS: Section[] = [
  {
    title: "1. What ShipLock does",
    body: "ShipLock performs read-only security analysis of your Supabase project. We probe your project's API endpoints using the credentials you provide — the same way an attacker would from the public internet — and report what we find. We do not modify, delete, or write any data to your project.",
  },
  {
    title: "2. Your credentials",
    body: "Your Supabase anon key and project URL are used solely during the scan and are never written to disk, logged, or stored in any database. Your service role key is never requested. We cannot recover your credentials after the scan completes.",
  },
  {
    title: "3. Your authorization",
    body: "By submitting a Supabase project URL for scanning, you represent and warrant that you own the project or have explicit written authorization from the project owner to conduct security testing. Scanning projects you do not own or have authorization to test may violate applicable laws. ShipLock is not responsible for unauthorized use of this service.",
  },
  {
    title: "4. Scope of analysis",
    body: "ShipLock is an automated security scanner, not a substitute for a professional security audit. Scan results reflect known vulnerability patterns at the time of the scan. A passing grade does not guarantee your project is secure — new vulnerabilities may exist that ShipLock does not currently check for. Always combine automated scanning with human security review for production systems.",
  },
  {
    title: "5. Limitation of liability",
    body: "ShipLock is provided as-is. We are not liable for any security incidents, data breaches, or damages arising from issues found — or not found — by our scanner. Our liability is limited to the fees paid in the month in which any claim arises.",
  },
  {
    title: "6. Pricing & billing",
    body: "$49.00 USD per month. Billed monthly via Stripe. Your subscription begins on the date of your first payment. You may cancel at any time through the Stripe billing portal — your access continues until the end of the current billing period. No partial-month refunds.",
  },
  {
    title: "7. Refund policy",
    body: "Scan results are delivered immediately upon payment. Because the service is consumed at the moment of scanning, we do not offer refunds after scan results have been delivered. If you believe there was an error with your payment or scan, contact support@shiplock.dev within 7 days.",
  },
  {
    title: "8. Acceptable use",
    body: "You may not use ShipLock to scan projects you do not own or have authorization to test. You may not use ShipLock to circumvent, attack, or destabilize Supabase infrastructure. Automated abuse of the scanner (bulk scanning, rate limit circumvention) will result in account termination without refund.",
  },
  {
    title: "9. Changes to these terms",
    body: "We may update these terms from time to time. Continued use of ShipLock after changes are posted constitutes acceptance of the updated terms. Material changes will be communicated via email.",
  },
  {
    title: "10. Contact",
    body: "Questions about these terms: support@shiplock.dev",
  },
];

const PRIVACY_COLLECT = [
  { label: "Email address", detail: "When you create an account or pay — used to send receipts, security alerts, and let you log in." },
  { label: "Project URL hash", detail: "A one-way SHA-256 hash of your Supabase project URL. We cannot reverse this to recover your URL." },
  { label: "Security grade (A–F)", detail: "Stored so we can alert you if your grade drops and show you your scan history." },
  { label: "Issue count", detail: "The number of security issues found — stored anonymously in our activity log." },
  { label: "Payment details", detail: "Processed and stored by Stripe. We never see your card number." },
];

const PRIVACY_NEVER_COLLECT = [
  { label: "Anon keys", detail: "Your Supabase anon key is used only during the scan and is never written to disk, logged, or stored anywhere." },
  { label: "Service role keys", detail: "We never ask for your service role key. If one is submitted, we return a CRITICAL alert and immediately discard it." },
  { label: "Database contents", detail: "The scanner reads zero rows from your database. All probes use limit=0 or limit=1 purely for access-check purposes." },
  { label: "Personal data from your app", detail: "We do not read, store, or transmit any data belonging to your end-users." },
];

const THIRD_PARTIES = [
  { name: "Stripe", purpose: "Payment processing. Subject to Stripe's Privacy Policy." },
  { name: "Resend", purpose: "Transactional email (receipts, alerts). Only your email address is shared." },
  { name: "PostHog", purpose: "Anonymous product analytics (page views, scan counts). No personal data." },
  { name: "Vercel", purpose: "Hosting. Processes request IPs for rate limiting. No data is retained." },
];

function TLDR({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-accent-indigo/20 bg-accent-indigo/[0.04] p-4">
      <p className="mb-1 text-xs font-semibold tracking-wide text-accent-indigo uppercase">TL;DR</p>
      <p className="text-sm leading-relaxed text-muted-foreground">{children}</p>
    </div>
  );
}

function Item({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <details className="group rounded-xl border border-border bg-card open:shadow-sm">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4 text-sm font-medium text-foreground">
        {title}
        <span className="shrink-0 text-muted-foreground transition-transform group-open:rotate-45">+</span>
      </summary>
      <div className="border-t border-border px-5 py-5">{children}</div>
    </details>
  );
}

export function LegalAccordion() {
  return (
    <div className="mx-auto flex max-w-2xl flex-col gap-3">
      <Item title="Terms of Service">
        <div className="flex flex-col gap-5">
          <TLDR>
            ShipLock performs read-only security analysis. We never store your credentials. By using
            this service you confirm you have authorization to test the project you submit. $49/month,
            cancel anytime.
          </TLDR>
          {TERMS.map((s) => (
            <div key={s.title} className="space-y-1.5">
              <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">{s.title}</h4>
              <p className="text-sm leading-relaxed text-muted-foreground">{s.body}</p>
            </div>
          ))}
        </div>
      </Item>

      <Item title="Privacy Policy">
        <div className="flex flex-col gap-5">
          <TLDR>
            We never store your API keys, database credentials, or any data from your Supabase project.
            We only store what&apos;s needed to run the service: your email, a hashed URL, and your scan
            grade.
          </TLDR>

          <div className="space-y-3">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">What we collect</h4>
            {PRIVACY_COLLECT.map((i) => (
              <div key={i.label} className="rounded-lg border border-border bg-secondary/40 p-3">
                <p className="mb-0.5 text-sm font-medium text-foreground">{i.label}</p>
                <p className="text-sm leading-relaxed text-muted-foreground">{i.detail}</p>
              </div>
            ))}
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">What we never collect</h4>
            {PRIVACY_NEVER_COLLECT.map((i) => (
              <div key={i.label} className="rounded-lg border border-border bg-secondary/40 p-3">
                <p className="mb-0.5 text-sm font-medium text-foreground">{i.label}</p>
                <p className="text-sm leading-relaxed text-muted-foreground">{i.detail}</p>
              </div>
            ))}
          </div>

          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">Data storage</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              All data is stored in Supabase (PostgreSQL) with Row Level Security enabled on every table.
              Your data is only accessible to you. Backups are encrypted. Data is stored in the US East
              region.
            </p>
          </div>

          <div className="space-y-3">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">Third-party services</h4>
            {THIRD_PARTIES.map((t) => (
              <div key={t.name} className="flex items-start gap-3 rounded-lg border border-border bg-secondary/40 p-3">
                <span className="mt-0.5 shrink-0 rounded border border-accent-indigo/25 bg-accent-indigo/10 px-1.5 py-0.5 text-[10px] font-semibold text-accent-indigo uppercase">
                  {t.name}
                </span>
                <p className="text-sm leading-relaxed text-muted-foreground">{t.purpose}</p>
              </div>
            ))}
          </div>

          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">Your rights</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              You can request deletion of your account and all associated data at any time. Email
              support@shiplock.dev with the subject line &quot;Delete my account&quot; and we will
              process your request within 30 days. You can also export your scan history from the
              dashboard at any time.
            </p>
          </div>

          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">Contact</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">Privacy questions: support@shiplock.dev</p>
          </div>
        </div>
      </Item>

      <Item title="Responsible Disclosure">
        <div className="flex flex-col gap-5">
          <TLDR>
            Found a security issue in ShipLock itself (not in a project you scanned)? Tell us before you
            tell anyone else, and we&apos;ll credit you and fix it fast.
          </TLDR>
          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">Scope</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              This policy covers vulnerabilities in ShipLock&apos;s own infrastructure — shiplock.dev, our
              API, our authentication, and our data handling. It does not cover findings our scanner
              reports about a third-party project you submitted for scanning; those belong to that
              project&apos;s owner.
            </p>
          </div>
          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">How to report</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              Email support@shiplock.dev with a description of the issue, steps to reproduce, and any
              relevant request/response details. We aim to acknowledge reports within 2 business days.
            </p>
          </div>
          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">What we ask</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              Give us a reasonable window to investigate and fix an issue before any public disclosure.
              Don&apos;t access, modify, or exfiltrate data beyond what&apos;s needed to demonstrate the
              issue. Don&apos;t run automated scanners against our production infrastructure without
              contacting us first.
            </p>
          </div>
          <div className="space-y-1.5">
            <h4 className="text-xs font-semibold tracking-wide text-foreground uppercase">What you can expect</h4>
            <p className="text-sm leading-relaxed text-muted-foreground">
              A good-faith investigation, a status update once we&apos;ve assessed severity, and public
              credit (if you want it) once a fix ships. We don&apos;t currently run a paid bounty program.
            </p>
          </div>
        </div>
      </Item>
    </div>
  );
}
