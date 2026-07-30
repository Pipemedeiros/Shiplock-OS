import Link from "next/link";
import { requireDashboardSession, getMonitoredProject } from "@/lib/dashboard";
import { getLatestScan, getScanTimeline } from "@/lib/scanHistory";
import { getWatchLog, getWatchStatus } from "@/lib/monitoring/watchLog";
import { auditJwtSigning, type JwtSigningPosture } from "@/lib/security/sessionAudit";
import { GUARDRAILS } from "@/lib/guardrails";
import { WatchPanel } from "@/components/d/WatchPanel";
import { GuardrailPanel } from "@/components/d/GuardrailPanel";
import { Reveal } from "@/components/d/bits";

// Watch — the history tab. Every monitoring pass, what changed, and the
// standing guardrails. Counts and metadata only; no fix content reaches here.
export default async function DashboardWatchPage() {
  const { userId, isPaid } = await requireDashboardSession();
  const latest = await getLatestScan(userId);

  const [watchLog, watchStatus, timeline] = latest
    ? await Promise.all([getWatchLog(userId), getWatchStatus(userId), getScanTimeline(userId)])
    : [[], null, []];

  // Live JWT-signing posture — externally checkable from the stored project
  // URL, no extra credential. Best-effort: any failure returns "unknown"
  // rather than throwing.
  let jwtPosture: JwtSigningPosture | null = null;
  if (isPaid) {
    const { projectUrl } = await getMonitoredProject(userId);
    if (projectUrl) {
      jwtPosture = await auditJwtSigning(projectUrl);
    }
  }

  if (!latest) {
    return (
      <section style={{ paddingTop: 40 }}>
        <h1 className="dxd-statement">The watch starts with your first audit.</h1>
        <p className="dxd-lede" style={{ margin: "16px 0 24px" }}>
          Once you&apos;ve run one, every re-check lands here — what ran, when, and what changed
          since the pass before it.
        </p>
        <Link href="/onboarding" className="dxd-btn dxd-btn-paper">
          Run your first audit
        </Link>
      </section>
    );
  }

  return (
    <>
      <section style={{ paddingTop: 32 }}>
        <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
          The watch · every pass on the record
        </p>
        <p className="dxd-lede" style={{ marginBottom: 20, fontSize: 14 }}>
          Silence is the default. A pass that finds nothing new says nothing — that&apos;s the
          product working, not a gap in it.
        </p>
        {watchStatus && <WatchPanel entries={watchLog} status={watchStatus} timeline={timeline} />}
      </section>

      {isPaid && (
        <Reveal>
          <GuardrailPanel guardrails={GUARDRAILS} jwtPosture={jwtPosture} />
        </Reveal>
      )}
    </>
  );
}
