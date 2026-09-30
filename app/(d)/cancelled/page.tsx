import Link from "next/link";
import type { Metadata } from "next";
import { StatusPage } from "@/components/v3/StatusPage";

export const metadata: Metadata = { title: "Subscription cancelled", robots: { index: false, follow: false } };

export default function Cancelled() {
  return (
    <StatusPage eyebrow="Subscription cancelled" title="We are sorry ShipLock did not earn its place.">
      <p className="v3-sub" style={{ fontSize: 16.5, maxWidth: 580 }}>
        Your subscription is cancelled and you will not be charged again. Paid features stay on until the end of
        the period you already paid for. Your account, repositories and findings stay where they are, and the free
        plan keeps working.
      </p>
      <p className="v3-sub" style={{ fontSize: 16.5, maxWidth: 580, marginTop: 14 }}>
        If one thing fell short, tell us what it was at{" "}
        <a href="mailto:support@shiplock.dev?subject=Why%20I%20cancelled">support@shiplock.dev</a>.
      </p>
      <div className="v3-row" style={{ gap: 12, marginTop: 28 }}>
        <Link href="/dashboard" className="v3-btn v3-primary">Back to your dashboard</Link>
        <Link href="/dashboard/settings" className="v3-btn v3-ghost">Settings</Link>
      </div>
    </StatusPage>
  );
}
