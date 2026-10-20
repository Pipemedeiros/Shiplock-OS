import type { Metadata } from "next";
import Link from "next/link";
import { getVerifiedReport, type VerifiedReport } from "@/lib/verified/report";
import { LockMark } from "@/components/d/Brand";

// The public, shareable assessment summary. No session — addressed by an
// unguessable token. Rebuilt 2026-09-03 against the audit pipeline.
//
// THE READER IS NOT THE CUSTOMER. It is a technical reviewer at the customer's
// enterprise prospect, who is deciding whether to believe the customer's
// security answer, and who will check this against the repository if anything
// reads as overstated. So the page is ordered the way that reader needs rather
// than the way a badge would flatter: what was assessed and how much of it
// could not be, then what was found, then the provenance, then the boundary.
//
// The green-badge layout this replaces put "Passing 16 of 16 checks" at the top
// of a project that had never run that check. There is no badge here.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Security assessment summary, ShipLock",
  description: "What ShipLock's last automated review of a repository assessed, and what it found.",
  robots: { index: false }, // per-customer, not for search indexes
};

const S = {
  card: {
    border: "1px solid var(--d-line, #1f2a3a)",
    borderRadius: 12,
    padding: "16px 18px",
    background: "var(--d-card, rgba(255,255,255,0.02))",
  },
  eyebrow: { fontSize: 12, opacity: 0.7, marginBottom: 10 } as const,
} as const;

function Figure({ label, value, tone }: { label: string; value: string; tone?: "bad" | "muted" }) {
  return (
    <div style={S.card}>
      <div style={{ fontSize: 22, fontWeight: 600, color: tone === "bad" ? "var(--crit, #e5484d)" : undefined, opacity: tone === "muted" ? 0.7 : 1 }}>
        {value}
      </div>
      <div className="dxd-mono" style={{ fontSize: 11, opacity: 0.65, marginTop: 6 }}>{label}</div>
    </div>
  );
}

function Coverage({ report }: { report: VerifiedReport }) {
  const a = report.assessment;
  if (!a) return null;

  if (!a.known) {
    return (
      <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)", maxWidth: "70ch" }}>
        This assessment ran before ShipLock recorded how much of the surface it could judge, so the
        share below is not available for it. That is a gap in the record, not a finding: it does not
        mean the whole surface was assessed.
      </p>
    );
  }

  const reasons = [
    a.reasons.identity > 0 ? `on ${a.reasons.identity}, the check that decides who is calling runs somewhere the review could not follow` : null,
    a.reasons.scope > 0 ? `on ${a.reasons.scope}, whether the query is narrowed to the caller could not be determined` : null,
    a.reasons.signature > 0 ? `on ${a.reasons.signature}, a signature or shared-secret check sits in a helper that could not be attributed` : null,
  ].filter(Boolean);

  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 12, marginBottom: 18 }}>
        <Figure label="ENDPOINTS REACHING DATA" value={String(a.dataTouching)} />
        <Figure label="ASSESSED" value={String(a.assessed)} />
        <Figure label="COULD NOT BE ASSESSED" value={`${a.unassessed} (${a.unassessedShare}%)`} tone={a.unassessedShare >= 25 ? "bad" : undefined} />
      </div>
      <p style={{ fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)", maxWidth: "70ch" }}>
        {a.unassessed === 0
          ? "Every endpoint that reaches data was judged."
          : `${a.unassessed} of the ${a.dataTouching} endpoints that reach data could not be judged: ${reasons.join("; ")}. `}
        {a.unassessed > 0 ? (
          <strong>
            Those endpoints are not reported as safe. They were not examined, and a real gap on one of
            them would look exactly like this.
          </strong>
        ) : null}
        {a.dataUnreadable > 0
          ? ` A further ${a.dataUnreadable} ${a.dataUnreadable === 1 ? "endpoint reaches" : "endpoints reach"} no data the review could see while importing code it could not follow, so their data access is out of view entirely.`
          : ""}
      </p>
    </>
  );
}

function ReportBody({ report }: { report: VerifiedReport }) {
  const fmt = (d: string | null) =>
    d ? new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : "Not recorded";

  return (
    <div className="dxd-shell" style={{ maxWidth: 860, margin: "0 auto", padding: "40px 20px 72px" }}>
      <nav style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 34 }}>
        <LockMark size={19} />
        <span className="dxd-mono" style={{ fontSize: 13 }}>ShipLock</span>
      </nav>

      {/* The result, with its own limitation inside the sentence. */}
      <h1 style={{ fontSize: 25, lineHeight: 1.35, margin: "0 0 12px", maxWidth: "26ch", fontWeight: 600 }}>
        {report.headline}
      </h1>

      {report.status === "never_assessed" ? (
        <p style={{ fontSize: 14.5, lineHeight: 1.7, color: "var(--d-muted)", maxWidth: "70ch" }}>
          This repository is connected to ShipLock, but no audit has completed. There is no result to
          report and nothing on this page should be read as one.
        </p>
      ) : (
        <>
          <p className="dxd-mono" style={{ fontSize: 12.5, opacity: 0.7, margin: "0 0 28px" }}>
            {report.repository}
            {report.commit ? ` · commit ${report.commit}` : ""} · assessed {fmt(report.assessedAt)}
            {report.ageDays !== null ? ` (${report.ageDays === 0 ? "today" : `${report.ageDays} days ago`})` : ""}
          </p>

          {report.stale ? (
            <p style={{ ...S.card, borderColor: "var(--warn, #c98a20)", fontSize: 13.5, lineHeight: 1.6, marginBottom: 28 }}>
              This assessment is more than a month old. The repository has probably changed since, and
              nothing here reflects those changes.
            </p>
          ) : null}

          <section aria-label="What was assessed" style={{ marginBottom: 30 }}>
            <h2 className="dxd-mono" style={S.eyebrow}>HOW MUCH OF THE SURFACE WAS ASSESSED</h2>
            <Coverage report={report} />
          </section>

          <section aria-label="What was found" style={{ marginBottom: 30 }}>
            <h2 className="dxd-mono" style={S.eyebrow}>WHAT WAS FOUND, ON THE PART THAT WAS ASSESSED</h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 12 }}>
              <Figure label="UNRESOLVED CRITICAL" value={String(report.openCritical)} tone={report.openCritical > 0 ? "bad" : undefined} />
              <Figure label="UNRESOLVED, ALL SEVERITIES" value={String(report.openTotal)} />
              {report.read ? <Figure label="FILES READ" value={String(report.read.files)} tone="muted" /> : null}
            </div>
          </section>
        </>
      )}

      {report.live ? (
        <section aria-label="The live site" style={{ marginBottom: 30 }}>
          <h2 className="dxd-mono" style={S.eyebrow}>WHAT THE LIVE SITE SHIPS</h2>
          {report.live.map((line) => (
            <p key={line} style={{ fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)", maxWidth: "70ch", margin: "0 0 6px" }}>{line}</p>
          ))}
        </section>
      ) : null}

      <section aria-label="Not covered" style={{ marginBottom: 30 }}>
        <h2 className="dxd-mono" style={S.eyebrow}>NOT COVERED BY THIS ASSESSMENT</h2>
        <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 10 }}>
          {report.notCovered.map((line) => (
            <li key={line} style={{ fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)", maxWidth: "70ch" }}>{line}</li>
          ))}
        </ul>
      </section>

      {/* Stated to the READER rather than to the customer. A disclaimer in our
          terms binds the customer who agreed to them, not the buyer relying on
          this page, and reliance by a non-expert on a specialist's public
          assertion is the negligent-misrepresentation fact pattern. */}
      <div style={{ borderTop: "1px solid var(--d-line,#1f2a3a)", paddingTop: 20, fontSize: 12.5, lineHeight: 1.65, opacity: 0.62 }}>
        <div className="dxd-mono" style={{ fontSize: 10.5, letterSpacing: "0.1em", marginBottom: 8 }}>
          WHAT THIS PAGE IS, AND ISN&apos;T
        </div>
        <p style={{ margin: 0 }}>
          {report.disclaimer} ShipLock accepts no liability to any reader for decisions taken in
          reliance on it.
        </p>
      </div>

      <footer style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12, marginTop: 26 }}>
        <span className="dxd-mono" style={{ fontSize: 11, opacity: 0.6 }}>Generated by ShipLock from the repository&apos;s source</span>
        <Link href="/coverage" className="dxd-mono" style={{ fontSize: 12 }}>What ShipLock checks →</Link>
      </footer>
    </div>
  );
}

export default async function VerifiedReportPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const report = await getVerifiedReport(token);

  // A disabled report and a nonexistent token are indistinguishable.
  if (!report) {
    return (
      <main className="dxd">
        <div className="dxd-shell" style={{ maxWidth: 560, margin: "0 auto", padding: "80px 20px", textAlign: "center" }}>
          <LockMark size={28} />
          <p className="dxd-lede" style={{ opacity: 0.75, marginTop: 18 }}>
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
