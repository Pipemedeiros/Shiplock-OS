import type { Metadata } from "next";
import Link from "next/link";
import { getVerifiedReport, type VerifiedReport } from "@/lib/verified/report";
import { LockMark } from "@/components/d/Brand";

// Public, shareable "ShipLock Verified" posture report. No session — addressed
// by an unguessable token. Renders an honest, scoped attestation (posture +
// scope + cadence), never the specific findings/fixes. Lives in the (d) route
// group only to inherit the design system/fonts; the URL is /verified/<token>.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Security posture report — ShipLock Verified",
  description: "A continuously-monitored security posture attestation by ShipLock.",
  robots: { index: false }, // per-customer report, not for search indexes
};

function Stat({ label, value, good }: { label: string; value: string; good?: boolean }) {
  return (
    <div
      style={{
        border: "1px solid var(--d-line, #1f2a3a)",
        borderRadius: 12,
        padding: "16px 18px",
        background: "var(--d-card, rgba(255,255,255,0.02))",
      }}
    >
      <div className="dxd-mono" style={{ fontSize: 11, opacity: 0.7, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 600, color: good ? "#4ade80" : "inherit" }}>{value}</div>
    </div>
  );
}

function ReportBody({ report }: { report: VerifiedReport }) {
  const verified = report.status === "verified";
  const fmt = (d: string | null) =>
    d ? new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" }) : "—";

  return (
    <div className="dxd-shell" style={{ maxWidth: 760, margin: "0 auto", padding: "48px 20px 64px" }}>
      <nav className="dxd-nav" aria-label="ShipLock" style={{ marginBottom: 40 }}>
        <span className="dxd-wordmark" style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <LockMark size={19} />
          ShipLock
        </span>
        <span className="dxd-mono" style={{ fontSize: 11, opacity: 0.7 }}>Verified report</span>
      </nav>

      {/* Status banner */}
      <div
        style={{
          display: "flex", alignItems: "center", gap: 12, padding: "14px 18px", borderRadius: 12,
          border: `1px solid ${verified ? "rgba(74,222,128,0.4)" : "var(--d-line,#1f2a3a)"}`,
          background: verified ? "rgba(74,222,128,0.08)" : "transparent", marginBottom: 28,
        }}
      >
        <span style={{ fontSize: 22 }}>{verified ? "🛡️" : "○"}</span>
        <div>
          <div style={{ fontWeight: 600 }}>
            {verified ? "Continuously monitored by ShipLock" : "Monitoring not currently active"}
          </div>
          <div className="dxd-mono" style={{ fontSize: 12, opacity: 0.75 }}>
            {report.projectHashSuffix ? `Project …${report.projectHashSuffix} · ` : ""}
            Last verified {fmt(report.lastVerifiedAt)}
          </div>
        </div>
      </div>

      <h1 className="dxd-statement" style={{ fontSize: 26, marginBottom: 8 }}>Security posture</h1>
      <p className="dxd-lede" style={{ opacity: 0.8, marginBottom: 24 }}>
        Passing <strong>{report.checksPassing}</strong> of {report.totalChecks} automated checks across the
        OWASP surface, under continuous monitoring.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 12, marginBottom: 32 }}>
        <Stat label="Checks passing" value={`${report.checksPassing} / ${report.totalChecks}`} good={report.checksPassing === report.totalChecks} />
        <Stat label="Open critical issues" value={String(report.openCriticalCount)} good={report.openCriticalCount === 0} />
        <Stat label="Issues resolved" value={String(report.issuesResolved)} />
        <Stat label="Traffic protection" value={report.trafficProtection ? "Active" : "—"} good={report.trafficProtection} />
        <Stat
          label="Session signing"
          value={report.sessionSigning === "asymmetric" ? "Asymmetric" : report.sessionSigning === "legacy" ? "Legacy" : "—"}
          good={report.sessionSigning === "asymmetric"}
        />
        <Stat label="Monitoring" value={report.monitored ? "Live" : "Off"} good={report.monitored} />
      </div>

      <section style={{ marginBottom: 28 }}>
        <h2 className="dxd-mono" style={{ fontSize: 12, opacity: 0.7, marginBottom: 10 }}>MONITORING CADENCE</h2>
        <ul style={{ display: "flex", flexWrap: "wrap", gap: 8, listStyle: "none", padding: 0 }}>
          {report.cadence.map((c) => (
            <li key={c} className="dxd-mono" style={{ fontSize: 12, padding: "6px 10px", border: "1px solid var(--d-line,#1f2a3a)", borderRadius: 8 }}>{c}</li>
          ))}
        </ul>
      </section>

      <section style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 20, marginBottom: 32 }}>
        <div>
          <h2 className="dxd-mono" style={{ fontSize: 12, opacity: 0.7, marginBottom: 10 }}>COVERED</h2>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 14, lineHeight: 1.7 }}>
            {report.scopeCovered.map((s) => <li key={s}>{s}</li>)}
          </ul>
        </div>
        <div>
          <h2 className="dxd-mono" style={{ fontSize: 12, opacity: 0.7, marginBottom: 10 }}>NOT COVERED BY THIS SCAN</h2>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 14, lineHeight: 1.7, opacity: 0.8 }}>
            {report.scopeNotCovered.map((s) => <li key={s}>{s}</li>)}
          </ul>
        </div>
      </section>

      {/* The honest boundary — rendered prominently, never buried. */}
      <p style={{ fontSize: 13, lineHeight: 1.6, opacity: 0.7, borderTop: "1px solid var(--d-line,#1f2a3a)", paddingTop: 20, marginBottom: 32 }}>
        {report.disclaimer}
      </p>

      <footer style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <span className="dxd-mono" style={{ fontSize: 11, opacity: 0.6 }}>Live report · verified by ShipLock</span>
        <Link href="/" className="dxd-mono" style={{ fontSize: 12 }}>Secure your app with ShipLock →</Link>
      </footer>
    </div>
  );
}

export default async function VerifiedReportPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const report = await getVerifiedReport(token);

  // Disabled or nonexistent token are indistinguishable — no enumeration.
  if (!report) {
    return (
      <main className="dxd">
        <div className="dxd-shell" style={{ maxWidth: 560, margin: "0 auto", padding: "80px 20px", textAlign: "center" }}>
          <LockMark size={28} />
          <h1 className="dxd-statement" style={{ fontSize: 22, margin: "20px 0 8px" }}>No active report</h1>
          <p className="dxd-lede" style={{ opacity: 0.75 }}>
            There is no active ShipLock report at this link.
          </p>
          <Link href="/" className="dxd-mono" style={{ fontSize: 13, display: "inline-block", marginTop: 20 }}>
            About ShipLock →
          </Link>
        </div>
      </main>
    );
  }

  return <main className="dxd"><ReportBody report={report} /></main>;
}
