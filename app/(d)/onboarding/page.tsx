import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { LockMark } from "@/components/d/Brand";
import { ConnectAndScanForm } from "@/components/d/ConnectAndScanForm";

// Post-sign-in onboarding: connect-your-stack step between OAuth and the
// dashboard. GitHub/Vercel/Cloudflare are presented honestly — none of
// those connection flows exist yet (no /api/monitor/enable, no GitHub App,
// no Vercel integration) — must stay consistent with
// app/dashboard-preview/page.tsx's own "Coming soon" labels. Database is
// the one real, live connection: the form below calls the real,
// unmodified POST /api/scan.
const SOURCES = [
  {
    name: "GitHub",
    provider: "Source scanning",
    description:
      "Leaked secrets and vulnerable dependencies caught in your repository before they ever reach production.",
  },
  {
    name: "Vercel",
    provider: "Deploy monitoring",
    description:
      "A fresh security pass triggered on every deploy, plus environment variable audits for weak or exposed secrets.",
  },
  {
    name: "Cloudflare",
    provider: "Edge protection",
    description:
      "Rate limiting, bot detection, and credential-stuffing protection at the edge — stopped before it reaches your app.",
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
        <ConnectAndScanForm />

        <section style={{ marginTop: 56 }}>
          <p className="dxd-panel-label" style={{ marginBottom: 14 }}>
            Rolling out — your account is ready either way
          </p>
          <div className="dxd-stakes">
            {SOURCES.map((s) => (
              <div className="dxd-connect-card" key={s.name} style={{ flexDirection: "column" }}>
                <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "flex-start" }}>
                  <h4>{s.name}</h4>
                  <span className="dxd-mono" style={{ fontSize: 10, color: "var(--d-muted)" }}>
                    Coming soon
                  </span>
                </div>
                <span className="dxd-scope" style={{ color: "var(--d-muted)" }}>
                  {s.provider}
                </span>
                <p>{s.description}</p>
              </div>
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
