import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { LogoLoop } from "@/components/marketing/logo-loop";

// Post-sign-in onboarding: connect-your-stack step between OAuth and the
// dashboard. Every source is presented honestly — none of the connection
// flows exist yet (no /api/monitor/enable, no GitHub App, no Vercel
// integration), so all three cards are "Coming soon" rather than buttons
// that fail when clicked. Continue never blocks on a connection.
const SOURCES = [
  {
    name: "Database",
    provider: "Supabase",
    description:
      "Row-level security drift, exposed tables, and public storage buckets — checked continuously against your live project.",
    path: "M13.6 2.1c.5-.6 1.5-.2 1.5.6v9.1h6.1c.9 0 1.4 1.1.8 1.8L11.9 21.9c-.5.6-1.5.2-1.5-.6v-9.1H4.3c-.9 0-1.4-1.1-.8-1.8L13.6 2.1Z",
  },
  {
    name: "GitHub",
    provider: "Source scanning",
    description:
      "Leaked secrets and vulnerable dependencies caught in your repository before they ever reach production.",
    path: "M12 2C6.48 2 2 6.58 2 12.2c0 4.5 2.87 8.31 6.84 9.66.5.1.68-.22.68-.5 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.24-3.37-1.24-.45-1.18-1.11-1.5-1.11-1.5-.9-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05a9.29 9.29 0 0 1 5 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.79-4.57 5.05.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.5A9.96 9.96 0 0 0 22 12.2C22 6.58 17.52 2 12 2Z",
  },
  {
    name: "Vercel",
    provider: "Deploy monitoring",
    description:
      "A fresh security pass triggered on every deploy, plus environment variable audits for weak or exposed secrets.",
    path: "M12 3 L22 21 H2 Z",
  },
];

export default async function OnboardingPage() {
  const supabase = await getSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/auth");
  }

  return (
    <main className="min-h-screen bg-background text-foreground">
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
          </div>
          <span className="text-sm text-muted-foreground">Signed in as {user.email}</span>
        </div>
      </header>

      <div className="mx-auto max-w-3xl px-6 py-14">
        <LogoLoop />

        <div className="mt-10 text-center">
          <p className="mb-3 text-xs font-semibold tracking-[0.14em] text-accent-indigo uppercase">
            Step 1 of 2
          </p>
          <h1 className="font-display text-3xl font-bold text-foreground sm:text-4xl">
            Connect your stack
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-lg leading-relaxed text-muted-foreground">
            ShipLock watches these sources for security drift. Connections are
            rolling out now — your account is ready either way.
          </p>
        </div>

        <div className="mt-10 grid gap-4 sm:grid-cols-3">
          {SOURCES.map((s) => (
            <div
              key={s.name}
              className="flex flex-col rounded-2xl border border-dashed border-border bg-secondary/30 p-6"
            >
              <div className="flex items-center justify-between">
                <svg viewBox="0 0 24 24" className="size-5 shrink-0 fill-current text-foreground/60" aria-hidden>
                  <path d={s.path} />
                </svg>
                <span className="rounded-full border border-border bg-background px-2.5 py-0.5 text-[11px] font-semibold tracking-wide text-muted-foreground uppercase">
                  Coming soon
                </span>
              </div>
              <p className="mt-4 text-sm font-semibold text-foreground/80">{s.name}</p>
              <p className="text-xs font-medium text-muted-foreground">{s.provider}</p>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{s.description}</p>
            </div>
          ))}
        </div>

        <div className="mt-10 flex flex-col items-center gap-4">
          <Link
            href="/dashboard-preview"
            className="rounded-lg bg-accent-indigo px-8 py-3.5 text-[15px] font-medium text-white shadow-sm transition-opacity hover:opacity-90"
          >
            Continue
          </Link>
          <Link
            href="/dashboard"
            className="text-sm text-muted-foreground transition-colors hover:text-foreground"
          >
            Skip to account settings
          </Link>
        </div>
      </div>
    </main>
  );
}
