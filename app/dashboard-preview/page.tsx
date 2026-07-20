import Link from "next/link";
import { ScrollReveal } from "@/components/marketing/scroll-reveal";
import { FloatingLines } from "@/components/marketing/floating-lines";

// Same class of bug as app/page.tsx: force dynamic rendering so this
// page's script nonces stay in sync with middleware's per-request CSP
// nonce instead of getting statically prerendered and going blank.
export const dynamic = "force-dynamic";

const ALERTS = [
  {
    severity: "Critical",
    text: "Storage bucket \"avatars\" made public",
    time: "2 hours ago",
  },
  {
    severity: "High",
    text: "RLS disabled on table \"orders\"",
    time: "6 hours ago",
  },
  {
    severity: "Medium",
    text: "No rate limit on /auth/v1/token",
    time: "1 day ago",
  },
  {
    severity: "Pass",
    text: "Service role key exposure — resolved",
    time: "3 days ago",
  },
];

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "text-sev-critical bg-sev-critical/10 border-sev-critical/25",
  High: "text-sev-high bg-sev-high/10 border-sev-high/25",
  Medium: "text-sev-medium bg-sev-medium/10 border-sev-medium/25",
  Pass: "text-sev-pass bg-sev-pass/10 border-sev-pass/25",
};

// Must stay consistent with app/onboarding/page.tsx — every source shown
// there as "Coming soon" is "Coming soon" here too. Do not flip any of
// these to "Connected" until a real connection flow ships.
const SOURCES = [
  {
    name: "GitHub",
    path: "M12 2C6.48 2 2 6.58 2 12.2c0 4.5 2.87 8.31 6.84 9.66.5.1.68-.22.68-.5 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.24-3.37-1.24-.45-1.18-1.11-1.5-1.11-1.5-.9-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05a9.29 9.29 0 0 1 5 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.79-4.57 5.05.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.5A9.96 9.96 0 0 0 22 12.2C22 6.58 17.52 2 12 2Z",
  },
  {
    name: "Supabase",
    path: "M13.6 2.1c.5-.6 1.5-.2 1.5.6v9.1h6.1c.9 0 1.4 1.1.8 1.8L11.9 21.9c-.5.6-1.5.2-1.5-.6v-9.1H4.3c-.9 0-1.4-1.1-.8-1.8L13.6 2.1Z",
  },
];

export default function DashboardPreviewPage() {
  return (
    <main className="min-h-screen bg-background text-foreground">
      {/* Unmistakable concept-preview banner — not real account data */}
      <div className="border-b border-accent-indigo/25 bg-accent-indigo/[0.06] px-6 py-2.5 text-center">
        <p className="text-xs font-semibold tracking-wide text-accent-indigo">
          Concept preview — product roadmap. Sample data, not a live account.
        </p>
      </div>

      <header className="border-b border-border px-6 py-5">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <div className="flex items-center gap-2">
            <svg viewBox="0 0 32 32" className="size-6 shrink-0" aria-hidden>
              <path fill="var(--foreground)" d="M16 2 L28 7 V16 C28 24 22 29 16 30 C10 29 4 24 4 16 V7 Z" />
              <path
                fill="var(--accent-indigo)"
                d="M13 15 C13 12 14.5 10 16 10 C17.5 10 19 12 19 15 L19 16 L20 16 C20.6 16 21 16.4 21 17 L21 23 C21 23.6 20.6 24 20 24 L12 24 C11.4 24 11 23.6 11 23 L11 17 C11 16.4 11.4 16 12 16 L13 16 Z"
              />
            </svg>
            <span className="text-[15px] font-semibold tracking-tight text-foreground">ShipLock</span>
            <span className="ml-2 rounded-full border border-accent-indigo/25 bg-accent-indigo/10 px-2.5 py-0.5 text-[11px] font-semibold tracking-wide text-accent-indigo uppercase">
              Concept preview
            </span>
          </div>
          <Link href="/" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
            ← Back to shiplock.dev
          </Link>
        </div>
      </header>

      <div className="mx-auto max-w-5xl px-6 py-12">
        <h1 className="font-display text-3xl font-bold text-foreground">Security dashboard</h1>
        <p className="mt-2 text-muted-foreground">acme-app.com · sample project, for illustration only</p>

        <div className="mt-10 grid gap-6 lg:grid-cols-[1fr_1.4fr]">
          {/* Health score — `isolate` keeps the -z-10 texture above the
              card's own background instead of vanishing behind it */}
          <div className="relative isolate overflow-hidden rounded-2xl border border-border bg-card p-7 shadow-sm">
            <FloatingLines />
            <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Security health</p>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="font-display text-5xl font-bold text-foreground">72</span>
              <span className="text-lg text-muted-foreground">/100</span>
            </div>
            <p className="mt-1 text-sm text-sev-high">3 issues need attention</p>
            <div className="mt-5 h-2 w-full overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-sev-medium"
                style={{ width: "72%", animation: "health-fill 0.9s cubic-bezier(0.16, 1, 0.3, 1)" }}
              />
            </div>

            <div className="mt-7 space-y-3">
              <p className="text-xs font-medium tracking-wide text-muted-foreground uppercase">Connected sources</p>
              {SOURCES.map((s) => (
                <div key={s.name} className="flex items-center justify-between rounded-lg border border-border bg-secondary/40 px-3 py-2">
                  <span className="flex items-center gap-2.5">
                    <svg viewBox="0 0 24 24" className="size-4 shrink-0 fill-current text-foreground/60" aria-hidden>
                      <path d={s.path} />
                    </svg>
                    <span className="text-sm font-medium text-foreground">{s.name}</span>
                  </span>
                  <span className="rounded-full border border-border bg-background px-2 py-0.5 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
                    Coming soon
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Alerts + roadmap card */}
          <div className="flex flex-col gap-6">
            <div className="rounded-2xl border border-border bg-card p-7 shadow-sm">
              <p className="mb-3 text-xs font-medium tracking-wide text-muted-foreground uppercase">Recent alerts</p>
              <div className="font-mono text-[13px]">
                {ALERTS.map((a, i) => (
                  <ScrollReveal key={a.text} delayMs={i * 90}>
                    <div className="flex items-center gap-3 border-b border-border/70 py-3 last:border-b-0">
                      <span
                        className={`inline-flex w-[72px] shrink-0 items-center justify-center rounded border px-1.5 py-0.5 text-[10px] font-semibold tracking-wide uppercase ${SEVERITY_STYLES[a.severity]}`}
                      >
                        {a.severity}
                      </span>
                      <span className="flex-1 truncate text-foreground/85">{a.text}</span>
                      <span className="shrink-0 text-xs text-muted-foreground">{a.time}</span>
                    </div>
                  </ScrollReveal>
                ))}
              </div>
            </div>

            {/* Coming soon — visually distinct, not a real clickable action */}
            <div className="rounded-2xl border border-dashed border-border bg-secondary/30 p-7">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold text-foreground/70">Generate PR fix</p>
                <span className="rounded-full border border-border bg-background px-2.5 py-0.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
                  Coming soon
                </span>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                Automatically open a pull request with a templated fix for safe, non-destructive issues —
                dependency bumps, missing headers, hardcoded secrets. Database, RLS, and auth changes will
                always stay alert-and-copy-paste only, never auto-applied.
              </p>
            </div>
          </div>
        </div>
      </div>
    </main>
  );
}
