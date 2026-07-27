import type { Metadata } from "next";
import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getLatestScan } from "@/lib/scanHistory";
import { getFixFindings } from "@/lib/fixes/findings";
import { SignOutButton } from "@/components/sign-out-button";
import { ManageBillingButton } from "@/components/d/ManageBillingButton";
import { LockMark } from "@/components/d/Brand";
import { DashboardTabs } from "@/components/d/DashboardTabs";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

// Shell shared by all four dashboard surfaces: the account bar, the section
// tabs, and the footer. Each page underneath loads only its own data.
export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { email, provider, isPaid, userId } = await requireDashboardSession();
  const latest = await getLatestScan(userId);

  // Tab badge only — a count, never fix content.
  const openCount = isPaid ? (await getFixFindings(userId)).length : 0;

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
              {latest?.project_url_hash && (
                <span className="dxd-mono" style={{ fontSize: 12, color: "var(--d-muted-light)" }}>
                  project ...{latest.project_url_hash.slice(-6)}
                </span>
              )}
              <span style={{ fontSize: 13 }}>{email}</span>
              <span
                className="dxd-mono"
                style={{ fontSize: 11, color: "var(--d-muted-light)", textTransform: "capitalize" }}
              >
                {provider}
              </span>
              <span className="dxd-mono" style={{ fontSize: 11 }}>
                {isPaid ? "Pro" : latest ? "Lapsed" : "Not subscribed"}
              </span>
              {(isPaid || latest) && <ManageBillingButton />}
              <SignOutButton />
            </div>
          </nav>

          <DashboardTabs findingCount={openCount} />
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body">
        {children}

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
          </span>
          <span>
            last scanned{" "}
            {latest?.created_at ? new Date(latest.created_at).toLocaleString() : "—"}
          </span>
        </footer>
      </div>
    </main>
  );
}
