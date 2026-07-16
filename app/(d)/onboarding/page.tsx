import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { LockMark } from "@/components/d/Brand";
import { ConnectAndScanForm } from "@/components/d/ConnectAndScanForm";
import { UpgradeButton } from "@/components/d/UpgradeButton";
import { Reveal } from "@/components/d/bits";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};


// Post-sign-in onboarding: connect-your-stack step between OAuth and the
// dashboard. Database is the live connection the form below drives (real,
// unmodified POST /api/scan). The cards beneath describe the rest of the
// retainer — all real capabilities the customer sets up from their dashboard
// after the first scan; kept honest about what needs a one-time setup step.
const INCLUDED = [
  {
    name: "Source scanning",
    provider: "GitHub · read-only",
    note: "connect your repo",
    description:
      "Committed secrets and vulnerable dependencies found in your repository — delivered as fix pull requests you review and merge. We never push to your code.",
  },
  {
    name: "Live traffic protection",
    provider: "Your edge · fails open",
    note: "one small file",
    description:
      "Turns credential stuffing, vulnerability scanners, and floods away from your login. It lives in your app — no DNS change — and if ShipLock is ever down, your app just serves normally.",
  },
  {
    name: "Every deploy, re-audited",
    provider: "Continuous",
    note: "one webhook",
    description:
      "A fresh scan on every production deploy, deep scans on a schedule, and critical checks hourly — you only hear from us when something new appears.",
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

  // Scanning is paid-only — /api/scan itself enforces this server-side too,
  // this is just so an unpaid signed-in user sees a subscribe CTA instead
  // of a form that would 402 on submit. Same RLS-scoped query pattern as
  // app/(d)/dashboard/page.tsx.
  const { data: profile } = await supabase
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();
  const isPaid = profile?.is_paid ?? false;

  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <span className="dxd-wordmark">
              <span className="dxd-wordmark-lock">
                <LockMark size={19} />
              </span>
              ShipLock
            </span>
            <span
              className="dxd-mono"
              style={{ fontSize: 12, color: "var(--d-muted-light)" }}
            >
              Signed in as {user.email}
            </span>
          </nav>
          <div className="dxd-onb-band">
            <p className="dxd-eyebrow">Step 1 of 2</p>
            <h1 className="dxd-display" style={{ fontSize: "clamp(34px,5.2vw,56px)" }}>
              Point us at the stack.
            </h1>
          </div>
        </div>
      </div>

      <div className="dxd-shell">
        {isPaid ? (
          <ConnectAndScanForm />
        ) : (
          <Reveal>
            <section className="dxd-connect-card" aria-label="Subscribe to run your first audit">
              <div>
                <h4>Put us on retainer to run your first audit</h4>
                <p>
                  Paste your Supabase URL and anon key the moment you&apos;re in, and the first
                  scan — grade, every finding, and a fix for each — runs immediately. The key we
                  ask for is the same public one your app already ships to every visitor; never
                  anything more.
                </p>
              </div>
              <span className="dxd-connect-cta">
                <UpgradeButton />
              </span>
            </section>
          </Reveal>
        )}

        <section style={{ marginTop: 56 }}>
          <p className="dxd-panel-label" style={{ marginBottom: 14 }}>
            The rest of the retainer — set up when you&apos;re ready
          </p>
          <div className="dxd-stakes">
            {INCLUDED.map((s, i) => (
              <Reveal key={s.name} delay={i * 80}>
                <div className="dxd-connect-card" style={{ flexDirection: "column", height: "100%" }}>
                  <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "flex-start", gap: 10 }}>
                    <h4>{s.name}</h4>
                    <span className="dxd-mono" style={{ fontSize: 10, color: "var(--d-bronze)", whiteSpace: "nowrap" }}>
                      {s.note}
                    </span>
                  </div>
                  <span className="dxd-scope" style={{ color: "var(--d-muted)" }}>
                    {s.provider}
                  </span>
                  <p>{s.description}</p>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
          </span>
        </footer>
      </div>
    </main>
  );
}
