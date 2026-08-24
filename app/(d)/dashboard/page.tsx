import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getLatestScan } from "@/lib/scanHistory";
import { getWatchStatus } from "@/lib/monitoring/watchLog";
import { getProtectionStatus, getRecentBlocks, getRecentThreats } from "@/lib/traffic/trafficLog";
import { getTrafficPulse, EMPTY_PULSE } from "@/lib/traffic/pulse";
import { buildSnippet, buildWebSnippet, buildExpressSnippet } from "@/lib/traffic/snippet";
import { getFixFindings } from "@/lib/fixes/findings";
import { loadExposure } from "@/lib/exposure/load";
import { fixLane } from "@/lib/fixes/lane";
import { env } from "@/lib/env";
import { PostureHeadline } from "@/components/d/CoverageBoard";
import { getLayerStatus, describeLayerStatus } from "@/lib/graph/layerStatus";
import { TrafficPanel } from "@/components/d/TrafficPanel";
import { TrafficPulse } from "@/components/d/TrafficPulse";
import { ExposurePanel } from "@/components/d/ExposurePanel";
import { UpgradeButton } from "@/components/d/UpgradeButton";
import { Reveal } from "@/components/d/bits";
import type { PreviewIssue, FullIssue } from "@/lib/types";

const TOTAL_CHECKS = 16; // lib/scanner.ts always runs the same 16 checks

// Overview — the "is everything alright?" page. Posture, the live edge, and
// what's waiting on the customer to merge. Detail lives on the other tabs.
export default async function DashboardOverviewPage() {
  const { userId, isPaid } = await requireDashboardSession();
  const latest = await getLatestScan(userId);

  // Paywall filtering happens here, explicitly, mirroring app/api/scan's own
  // pattern — never spread full_issues into props when the caller isn't paid.
  const issues: (PreviewIssue | FullIssue)[] = latest
    ? (isPaid ? latest.full_issues : latest.preview_issues) ?? []
    : [];

  const watchStatus = latest ? await getWatchStatus(userId) : null;

  // Which layers are actually feeding the correlation graph. Booleans only —
  // getLayerStatus never returns a token, installation id, or URL.
  const layerStatus = await getLayerStatus(userId);

  // Live traffic protection — paid only, and independent of scan findings
  // (it's about inbound traffic). The ingest token is a live credential, so
  // the install snippet is only ever built for the paid owner.
  const [protectionStatus, trafficBlocks, trafficThreats, trafficPulse, exposure] = isPaid
    ? await Promise.all([
        getProtectionStatus(userId),
        getRecentBlocks(userId),
        getRecentThreats(userId),
        // Proof-of-work: the one number that is large and true every day.
        // Blocks and findings are both rare by design, so without this the
        // dashboard reads as "nothing is happening" — see lib/traffic/pulse.ts.
        getTrafficPulse(userId),
        // A21 exposure. Renders nothing at all when the inventory has not been
        // collected — "we have not looked" must never appear as a number.
        loadExposure(userId),
      ])
    : [null, [], [], EMPTY_PULSE, null];

  const trafficSnippet = protectionStatus?.ingestToken
    ? buildSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
    : null;

  // Count only — the fix content itself lives on the Risks tab. "Waiting on
  // you" means fixes that land as a pull request; deep-link fixes (a Supabase
  // toggle, a secret rotation) aren't merged, so they're not listed here.
  const fixFindings = isPaid ? await getFixFindings(userId) : [];
  const prReady = fixFindings.filter((f) => fixLane(f).method !== "deep-link");

  if (!latest) {
    return (
      <section className="dxd-dash-hero">
        <p className="dxd-eyebrow">The coverage board</p>
        <h1 className="dxd-statement">You haven&apos;t run an audit yet.</h1>
        <p className="dxd-lede" style={{ margin: "16px 0 24px" }}>
          {isPaid
            ? "Connect your Supabase project to run the first audit — findings and the fix for every issue."
            : "Put us on retainer, then connect your Supabase project to run the first audit."}
        </p>
        <Link href="/onboarding" className="dxd-btn dxd-btn-paper">
          {isPaid ? "Run your first audit" : "Get started"}
        </Link>
      </section>
    );
  }

  return (
    <>
      <section className="dxd-dash-hero">
        <p className="dxd-eyebrow">The coverage board</p>
        <PostureHeadline
          issues={issues}
          totalChecks={TOTAL_CHECKS}
          layerLine={describeLayerStatus(layerStatus)}
          nextLayer={
            layerStatus.nextUp
              ? { label: layerStatus.nextUp.label, href: "/dashboard/settings" }
              : null
          }
        />
        <p className="dxd-lede" style={{ marginTop: 18, fontSize: 14 }}>
          {watchStatus?.lastDeepScanAt
            ? `Last deep audit ${new Date(watchStatus.lastDeepScanAt).toLocaleString()}. Every pull request is re-checked as it opens.`
            : "Every pull request is re-checked as it opens, with a deep audit on schedule."}{" "}
          <Link href="/dashboard/activity">See the watch log →</Link>
        </p>
      </section>

      {/* Waiting on you — the only action-shaped thing on this page. */}
      {isPaid && (
        <section style={{ marginTop: 40 }} aria-label="Waiting on you">
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
            Waiting on you
          </p>
          {prReady.length === 0 ? (
            <div className="dxd-surface">
              <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: "var(--d-muted)" }}>
                Nothing needs merging. When a finding has a fix we can prepare, it arrives here as
                a pull request you review and merge — we never write to your database.
              </p>
            </div>
          ) : (
            <div className="dxd-surface">
              <p style={{ margin: "0 0 14px", fontSize: 14, lineHeight: 1.7 }}>
                <b>
                  {prReady.length} fix{prReady.length === 1 ? "" : "es"}
                </b>{" "}
                {prReady.length === 1 ? "is" : "are"} ready to open as a reviewable pull request.
                You read the diff, you merge it, your own deploy applies it.
              </p>
              <ul style={{ margin: "0 0 16px", paddingLeft: 18, display: "grid", gap: 6 }}>
                {prReady.slice(0, 4).map((f) => (
                  <li key={f.id} style={{ fontSize: 13.5, lineHeight: 1.6 }}>
                    {f.title}
                  </li>
                ))}
              </ul>
              <Link href="/dashboard/risks" className="dxd-btn">
                Review the fixes
              </Link>
            </div>
          )}
        </section>
      )}

      {isPaid && (
        <Reveal>
          <TrafficPulse pulse={trafficPulse} />
        </Reveal>
      )}

      {isPaid && (
        <Reveal>
          <ExposurePanel summary={exposure} />
        </Reveal>
      )}

      {isPaid && protectionStatus && trafficSnippet && (
        <Reveal>
          <TrafficPanel
            status={protectionStatus}
            blocks={trafficBlocks}
            threats={trafficThreats}
            snippet={trafficSnippet}
            webSnippet={
              protectionStatus.ingestToken
                ? buildWebSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
                : ""
            }
            expressSnippet={
              protectionStatus.ingestToken
                ? buildExpressSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
                : ""
            }
          />
        </Reveal>
      )}

      <section style={{ marginTop: 40 }} aria-label="Your connected stack">
        <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
          Your stack · what the watch can see
        </p>
        <div className="dxd-stack">
          <div className="dxd-stack-tile">
            <span className="dxd-stack-name">
              <span className="dxd-stack-cat">Database</span>
              <h3>Supabase</h3>
              <span className="dxd-stack-role">public key only, never more</span>
            </span>
            <span className="dxd-stack-status dxd-chip dxd-chip-verified">Connected</span>
          </div>
          <div className="dxd-stack-tile">
            <span className="dxd-stack-name">
              <span className="dxd-stack-cat">Source</span>
              <h3>GitHub</h3>
              <span className="dxd-stack-role">contents: read-only</span>
            </span>
            <Link href="/dashboard/settings" className="dxd-mono" style={{ fontSize: 11 }}>
              Manage →
            </Link>
          </div>
        </div>
      </section>

      {!isPaid && (
        <section style={{ marginTop: 40 }}>
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
            Terms of engagement
          </p>
          <div className="dxd-connect-card">
            <div>
              <h4>Your retainer lapsed</h4>
              <p>
                Fixes, the watch, and the live edge all pause when the subscription does.
                Resubscribe to see this audit&apos;s findings in full and pick the watch back up.
              </p>
            </div>
            <span className="dxd-connect-cta">
              <UpgradeButton />
            </span>
          </div>
        </section>
      )}
    </>
  );
}
