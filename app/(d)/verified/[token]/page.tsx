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
// of a project that had never run that check. There is no badge here. Moved to
// the v3 design 2026-10-20: the navy masthead carries the result, the cards
// carry the gaps and the counts, in that order.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Security assessment summary, ShipLock",
  description: "What ShipLock's last automated review of a repository assessed, and what it found.",
  robots: { index: false }, // per-customer, not for search indexes
};

function Figure({ label, value, tone }: { label: string; value: string; tone?: "crit" | "warn" }) {
  return (
    <div className={tone ? `v3-metric tone-${tone}` : "v3-metric"}>
      <span className="v3-metric-value">{value}</span>
      <span className="v3-metric-label">{label}</span>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="v3-card" aria-label={title}>
      <div className="v3-hd"><h2 className="v3-eyebrow">{title}</h2></div>
      <div className="v3-card-p">{children}</div>
    </section>
  );
}

function Coverage({ report }: { report: VerifiedReport }) {
  const a = report.assessment;
  if (!a) return null;

  if (!a.known) {
    return (
      <p className="v3-vr-p">
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

  // A gap is not a finding, so a large unassessed share reads in warn, never crit.
  return (
    <>
      <div className="v3-vr-figs">
        <Figure label="Endpoints reaching data" value={String(a.dataTouching)} />
        <Figure label="Assessed" value={String(a.assessed)} />
        <Figure label="Could not be assessed" value={`${a.unassessed} (${a.unassessedShare}%)`} tone={a.unassessedShare >= 25 ? "warn" : undefined} />
      </div>
      <p className="v3-vr-p">
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

function Masthead({ children }: { children?: React.ReactNode }) {
  return (
    <header className="v3-band">
      <div className="v3-narrow">
        <nav className="v3-nav-top">
          <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
        </nav>
        {children}
      </div>
    </header>
  );
}

function ReportBody({ report }: { report: VerifiedReport }) {
  const fmt = (d: string | null) =>
    d ? new Date(d).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" }) : "Not recorded";
  const age = report.ageDays === null ? "" : ` (${report.ageDays === 0 ? "today" : `${report.ageDays} days ago`})`;

  return (
    <>
      <Masthead>
        {/* The result, with its own limitation inside the sentence. */}
        <div className="v3-vr-head">
          <p className="v3-vr-kicker">Security assessment summary</p>
          <h1 className="v3-serif">{report.headline}</h1>
          {report.status === "assessed" ? (
            <p className="v3-mono v3-vr-prov">
              {`${report.repository}${report.commit ? ` · commit ${report.commit}` : ""} · assessed ${fmt(report.assessedAt)}${age}`}
            </p>
          ) : null}
        </div>
      </Masthead>

      <div className="v3-narrow v3-stack v3-vr-body">
        {report.status === "never_assessed" ? (
          <p className="v3-vr-p">
            This repository is connected to ShipLock, but no audit has completed. There is no result to
            report and nothing on this page should be read as one.
          </p>
        ) : (
          <>
            {report.stale ? (
              <p className="v3-card v3-card-p v3-card-warn v3-vr-p v3-vr-stale">
                This assessment is more than a month old. The repository has probably changed since, and
                nothing here reflects those changes.
              </p>
            ) : null}

            <Section title="How much of the surface was assessed">
              <Coverage report={report} />
            </Section>

            <Section title="What was found, on the part that was assessed">
              <div className="v3-vr-figs">
                <Figure label="Unresolved critical" value={String(report.openCritical)} tone={report.openCritical > 0 ? "crit" : undefined} />
                <Figure label="Unresolved, all severities" value={String(report.openTotal)} />
                {report.read ? <Figure label="Files read" value={String(report.read.files)} /> : null}
              </div>
            </Section>
          </>
        )}

        {report.live ? (
          <Section title="What the live site ships">
            {report.live.map((line) => <p key={line} className="v3-vr-p">{line}</p>)}
          </Section>
        ) : null}

        <Section title="Not covered by this assessment">
          <ul className="v3-list v3-vr-list">
            {report.notCovered.map((line) => <li key={line} className="v3-row-pad">{line}</li>)}
          </ul>
        </Section>

        {/* Stated to the READER rather than to the customer. A disclaimer in our
            terms binds the customer who agreed to them, not the buyer relying on
            this page, and reliance by a non-expert on a specialist's public
            assertion is the negligent-misrepresentation fact pattern. */}
        <div className="v3-vr-terms">
          <h2 className="v3-eyebrow">What this page is, and isn&apos;t</h2>
          <p className="v3-small">
            {report.disclaimer} ShipLock accepts no liability to any reader for decisions taken in
            reliance on it.
          </p>
        </div>

        <footer className="v3-between v3-small" style={{ flexWrap: "wrap" }}>
          <span>Generated by ShipLock from the repository&apos;s source</span>
          <Link href="/coverage" className="v3-vr-link">What ShipLock checks</Link>
        </footer>
      </div>
    </>
  );
}

export default async function VerifiedReportPage({ params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;
  const report = await getVerifiedReport(token);

  // A disabled report and a nonexistent token are indistinguishable.
  if (!report) {
    return (
      <main className="v3 v3-vr">
        <Masthead />
        <div className="v3-narrow v3-vr-body">
          <p className="v3-vr-p">There is no active ShipLock report at this link.</p>
          <Link href="/" className="v3-vr-link" style={{ display: "inline-block", marginTop: 14 }}>About ShipLock</Link>
        </div>
      </main>
    );
  }

  return <main className="v3 v3-vr"><ReportBody report={report} /></main>;
}
