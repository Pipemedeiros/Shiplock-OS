import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
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
  const [runs, evidence, ai, providers, traffic] = await Promise.all([getRuns(userId, 1), getEvidenceCoverage(userId),
    getAiActivity(userId), getProviderCoverage(userId), getTrafficSources(userId)]);
  // GitHub tree reads for rate-limit offers; any failure just offers nothing.
  const hotRoutes = await getHotRoutes(userId).catch(() => ({}));
  const latest = runs[0];
  // G1: the same rules the PR check enforces and MCP serves.
  const repo = latest ? (await getRepositories(userId)).find((r) => r.fullName === latest.fullName) : undefined;
  const source = repo ? await loadRepositoryGraphSource(userId, repo.id) : null;
  const guardrails = repo && source?.routes ? deriveGuardrails(source.routes, { repository: repo.fullName, commit: null }) : null;

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">What we read, and what we did not</p>
          <h1 className="v3-serif">Coverage</h1>
        </div>
      </div>

      {/* Work handed to the customer's own AI (10B-2d). Unanswered is not clean. */}
      <div className="v3-card" style={{ marginBottom: 24 }}>
        <div className="v3-hd">
          <h2 className="v3-eyebrow">Your AI checks</h2>
        </div>
        <div className="v3-card-p"><AiChecks activity={ai} /></div>
      </div>

      {/* Latest read per connected provider (5A-3). */}
      <div className="v3-card" style={{ marginBottom: 24 }}>
        <div className="v3-hd">
          <h2 className="v3-eyebrow">Guardrails</h2>
        </div>
        <div className="v3-card-p"><GuardrailList guardrails={guardrails} /></div>
      </div>

      <div className="v3-card" style={{ marginBottom: 24 }}>
        <div className="v3-hd">
          <h2 className="v3-eyebrow">Connected providers</h2>
        </div>
        <div className="v3-card-p"><ProviderCoverage coverage={providers} /></div>
      </div>

      {/* Per repository traffic source (Q3 / 2F-5). */}
      <div className="v3-card" style={{ marginBottom: 24 }}>
        <div className="v3-hd">
          <h2 className="v3-eyebrow">Traffic</h2>
        </div>
        <div className="v3-card-p"><TrafficSources sources={traffic} offers={hotRoutes} /></div>
      </div>

      <div className="v3-card" style={{ marginBottom: 24 }}>
        <div className="v3-hd">
          <h2 className="v3-eyebrow">Stored evidence</h2>
        </div>
        <div className="v3-card-p">
          <p className="v3-small" style={{ marginBottom: 16 }}>
            Evidence across this account, separate from the repository audit below.
            Dates show when information was recorded, not when your provider last changed it.
            A complete collection does not mean the application is secure.
          </p>
          {!evidence.available ? (
            <p>We could not load evidence history. Its age and completeness are unknown.</p>
          ) : evidence.items.length === 0 ? (
            <p>No stored collector evidence is available yet.</p>
          ) : (
            <ul className="v3-small">
              {evidence.items.map((item) => (
                <li key={item.label} style={{ marginBottom: 12 }}>
                  <strong>{item.label}</strong>{": "}
                  {item.completeness === "complete" ? "Collection complete" : item.completeness === "partial" ? "Partial collection" : "Completeness unknown"}
                  <br />
                  {item.recordedAt ? <time dateTime={item.recordedAt}>Recorded {item.recordedAt.replace("T", " ").replace(".000Z", " UTC").replace("Z", " UTC")}</time> : "Recording date unknown"}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {!latest ? (
        <div className="v3-empty">
          <p>No audit has run yet.</p>
          <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 16 }}>
            Run the first audit
          </Link>
        </div>
      ) : (
        <div className="v3-stack">
          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Read in the last audit</h2>
              <span className="v3-small">{new Date(latest.startedAt).toLocaleString()}</span>
            </div>
            <div className="v3-card-p v3-grid-3">
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.filesRead ?? 0}</p>
                <p className="v3-small">files</p>
              </div>
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.entriesFound ?? 0}</p>
                <p className="v3-small">application entries</p>
              </div>
              <div>
                <p className="v3-serif" style={{ fontSize: 26 }}>{latest.tablesFound ?? 0}</p>
                <p className="v3-small">tables</p>
              </div>
            </div>
          </div>

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Not covered</h2>
              <span className="v3-small">And what would change it</span>
            </div>
            <div className="v3-card-p v3-cov">
              {latest.coverage.length === 0 ? (
                <p className="v3-small">No gaps were recorded for this run.</p>
              ) : (
                latest.coverage.map((c) => (
                  <div key={c.name}>
                    <b>{c.name}</b>
                    <span style={{ fontSize: 14, color: "var(--muted)" }}>
                      {c.why}
                      <small style={{ display: "block", marginTop: 5, fontFamily: "inherit", fontSize: 13 }}>
                        {c.effect}
                      </small>
                    </span>
                    {c.upgrade ? (
                      <Link href="/dashboard/settings" className="v3-btn v3-btn-sm v3-ghost">{c.upgrade}</Link>
                    ) : (
                      <span className="v3-small">Nothing to connect</span>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="v3-card v3-card-p">
            <p className="v3-sub" style={{ fontSize: 14, maxWidth: 720 }}>
              Connecting a read-only database role lets the audit read your access rules directly
              instead of inferring them from code. It is not a setup step and nothing is withheld
              without it. If someone has asked you a security question, the same picture as this
              page (what was assessed, what could not be, what is open) can be published at a
              private link from <Link href="/dashboard/settings">Settings</Link>.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
