import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { loadRepositoryDeploy, loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { deriveGuardrails } from "@/lib/guardrails/guardrails";
import { GuardrailList } from "@/components/v3/GuardrailList";
import { getEvidenceCoverage } from "@/lib/graph/evidenceCoverage";
import { getAiActivity } from "@/lib/intelligence/activity";
import { AiChecks } from "@/components/v3/AiChecks";
import { getProviderCoverage } from "@/lib/monitoring/providerCoverage";
import { ProviderCoverage } from "@/components/v3/ProviderCoverage";
import { getTrafficSources } from "@/lib/traffic/sourceStatus";
import { TrafficSources } from "@/components/v3/TrafficSources";
import { getHotRoutes } from "@/lib/traffic/hotRoutes";
import { When } from "@/components/v3/When";
import { Fold } from "@/components/v3/Fold";
import { auditState } from "@/lib/verdict";
import { loadLiveReach } from "@/lib/chain/liveReach";
import { shadowRoutes, shadowRoutesFromRuns } from "@/lib/chain/shadowRoutes";
import { LiveSite, liveSiteStatus } from "@/components/v3/LiveSite";
import { productionLine } from "@/lib/chain/productionLine";
import { unboundAppUrl } from "@/lib/deep/appUrlStore";
import { ConfirmServes } from "@/components/v3/ConfirmServes";

export const metadata = { title: "Coverage" };

/**
 * What the last audit did not reach.
 *
 * This page exists because absent is not the same as clean. A tool that only
 * ever reports what it found lets a thinner audit look like a better one, and
 * the customer has no way to tell the difference. Every note here is generated
 * from what actually happened in the run.
 */
export default async function Coverage() {
  const { userId } = await requireDashboardSession();
  const [runs, evidence, ai, providers, traffic, hotRoutes, repos, live] = await Promise.all([getRuns(userId), getEvidenceCoverage(userId),
    getAiActivity(userId), getProviderCoverage(userId), getTrafficSources(userId),
    // GitHub tree reads for rate-limit offers; any failure just offers nothing.
    getHotRoutes(userId).catch(() => ({})), getRepositories(userId), loadLiveReach(userId).catch(() => null)]);
  // What the last FINISHED audit did not reach; one still running has read
  // nothing yet and must not read as "nothing unread".
  const latest = auditState(runs).finished;
  // G1: the same rules the PR check enforces and MCP serves.
  const repo = latest ? repos.find((r) => r.fullName === latest.fullName) : undefined;
  const source = repo ? await loadRepositoryGraphSource(userId, repo.id) : null;
  const guardrails = repo && source?.routes ? deriveGuardrails(source.routes, { repository: repo.fullName, commit: null }) : null;

  // The outside view: what the live site requests that the bound repository's
  // newest stored routes do not declare.
  const bound = live ? repos.find((r) => r.id === live.repositoryId) ?? null : null;
  const shadow = bound ? shadowRoutesFromRuns(live, runs, bound.fullName) : shadowRoutes(null, null);
  // Is it live? The production deploy of the bound repository, else the audited one.
  const deployRepo = bound ?? repo;
  const [deploy, unbound] = await Promise.all([deployRepo ? loadRepositoryDeploy(userId, deployRepo.id).catch(() => null) : null,
    bound ? null : unboundAppUrl(userId).catch(() => null)]);

  const aiStatus = !ai.available ? "Unavailable" : ai.paused ? "Not running" : `${ai.checks.length} ${ai.checks.length === 1 ? "check" : "checks"}`;
  const providerStatus = !providers.available ? "Unavailable"
    : providers.items.length === 0 ? "None connected" : `${providers.items.filter((p) => p.state === "complete").length} of ${providers.items.length} read in full`;
  const trafficStatus = !traffic.available ? "Unavailable" : `${traffic.items.length} ${traffic.items.length === 1 ? "repository" : "repositories"}`;
  const evidenceStatus = !evidence.available ? "Unavailable" : `${evidence.items.length} ${evidence.items.length === 1 ? "source" : "sources"}`;

  return (
    <>
      <div className="v3-page-hd">
        <div>
          {latest ? <p className="v3-eyebrow">{latest.fullName} · Last audit <When at={latest.startedAt} /></p> : null}
          <h1>Coverage</h1>
        </div>
      </div>

      <div className="v3-stack">
        {!latest ? (
          <div className="v3-empty">
            <p>No audits yet.</p>
            <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 16 }}>Run an audit</Link>
          </div>
        ) : (
          <>
            <div className="v3-metrics">
              <Stat label="Files read" value={latest.filesRead ?? 0} />
              <Stat label="Entry points" value={latest.entriesFound ?? 0} />
              <Stat label="Tables" value={latest.tablesFound ?? 0} />
              <Stat label="Not checked" value={latest.coverage.length} warn />
            </div>

            <div className="v3-card">
              <div className="v3-hd">
                <h2 className="v3-eyebrow">Not checked</h2>
              </div>
              <div className="v3-card-p v3-cov">
                {latest.coverage.length === 0 ? (
                  <p className="v3-small">No gaps were recorded for this audit.</p>
                ) : (
                  latest.coverage.map((c) => (
                    <div key={c.name}>
                      <b>{c.name}</b>
                      <span style={{ fontSize: 14, color: "var(--muted)" }}>
                        {c.why}
                        <small style={{ display: "block", marginTop: 5, fontFamily: "inherit", fontSize: 13 }}>{c.effect}</small>
                      </span>
                      {c.upgrade ? <Link href="/dashboard/settings" className="v3-btn v3-btn-sm v3-ghost">{c.upgrade}</Link>
                        : <span className="v3-small">Nothing to connect</span>}
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        )}

        {/* Work handed to the customer's own AI (10B-2d). Unanswered is not clean. */}
        <Fold title="AI checks" status={aiStatus}><AiChecks activity={ai} /></Fold>
        <Fold title="Guardrails" status={guardrails ? `${guardrails.rules.length} rules` : "Not derived"}><GuardrailList guardrails={guardrails} /></Fold>
        <Fold title="Live site" open={Boolean(unbound)} status={unbound ? "Confirm the repository" : liveSiteStatus(bound ? live : null, shadow)}>
          {deployRepo ? <p className="v3-small" style={{ marginBottom: 12 }}><strong>{deployRepo.fullName}</strong>: {productionLine(deploy)}</p> : null}
          {unbound ? <ConfirmServes url={unbound.url} repositories={unbound.repositories} />
            : <LiveSite live={bound ? live : null} repository={bound?.fullName ?? null} shadow={shadow} />}
        </Fold>
        {/* Latest read per connected provider (5A-3). */}
        <Fold title="Providers" status={providerStatus}><ProviderCoverage coverage={providers} /></Fold>
        {/* Per repository traffic source (Q3 / 2F-5). */}
        <Fold title="Traffic" status={trafficStatus}><TrafficSources sources={traffic} offers={hotRoutes} /></Fold>
        <Fold title="Stored evidence" status={evidenceStatus}>
          <p className="v3-small" style={{ marginBottom: 16 }}>
            Dates show when evidence was recorded, not when your provider last changed. A complete collection does not mean the application is secure.
          </p>
          {!evidence.available ? (
            <p>Evidence history could not be loaded. Its age and completeness are unknown.</p>
          ) : evidence.items.length === 0 ? (
            <p>No stored evidence yet.</p>
          ) : (
            <ul className="v3-small">
              {evidence.items.map((item) => (
                <li key={item.label} style={{ marginBottom: 12 }}>
                  <strong>{item.label}</strong>{": "}
                  {item.completeness === "complete" ? "Complete" : item.completeness === "partial" ? "Partial" : "Completeness unknown"}
                  {" · "}
                  {item.recordedAt ? <When at={item.recordedAt} /> : "Date unknown"}
                </li>
              ))}
            </ul>
          )}
        </Fold>
      </div>
    </>
  );
}

function Stat({ label, value, warn = false }: { label: string; value: number; warn?: boolean }) {
  return (
    <div className={`v3-metric${warn && value > 0 ? " tone-warn" : ""}`}>
      <span className="v3-metric-label">{label}</span>
      <b className="v3-metric-value">{value}</b>
    </div>
  );
}
