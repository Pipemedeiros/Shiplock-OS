import Link from "next/link";
import { requireDashboardSession, getMonitoredProject } from "@/lib/dashboard";
import { getLatestScan } from "@/lib/scanHistory";
import { getFixFindings } from "@/lib/fixes/findings";
import { getSupabaseAdmin } from "@/lib/supabase";
import { buildAgentBrief } from "@/lib/agentBrief";
import { env } from "@/lib/env";
import { FindingsBoard } from "@/components/d/CoverageBoard";
import { FixesPanel } from "@/components/d/FixesPanel";
import { AgentBrief } from "@/components/d/AgentBrief";
import { GitHubPanel, type SourceFinding } from "@/components/d/GitHubPanel";
import { UpgradeButton } from "@/components/d/UpgradeButton";
import { Reveal } from "@/components/d/bits";
import type { PreviewIssue, FullIssue } from "@/lib/types";

const TOTAL_CHECKS = 16;

// Findings — everything that's open, and the fix for each. This is the page
// the paywall actually protects: full_issues (fix + codefix) only ever reaches
// it when the CURRENT caller is paid.
export default async function DashboardFindingsPage() {
  const { userId, isPaid } = await requireDashboardSession();
  const latest = await getLatestScan(userId);

  const issues: (PreviewIssue | FullIssue)[] = latest
    ? (isPaid ? latest.full_issues : latest.preview_issues) ?? []
    : [];

  const fixFindings = isPaid ? await getFixFindings(userId) : [];
  const { projectRef } = isPaid
    ? await getMonitoredProject(userId)
    : { projectRef: null };

  // GitHub source findings — only once the App is registered.
  const githubConfigured = Boolean(env.GITHUB_APP_SLUG);
  let githubConnected = false;
  let sourceFindings: SourceFinding[] = [];
  if (isPaid && githubConfigured) {
    const admin = getSupabaseAdmin();
    const [{ data: gh }, { data: findings }] = await Promise.all([
      admin.from("user_profiles").select("github_installation_id").eq("id", userId).maybeSingle(),
      admin
        .from("deep_findings")
        .select("title, severity, consequence")
        .eq("user_id", userId)
        .eq("source", "github")
        .is("archived_at", null)
        .order("detected_at", { ascending: false })
        .limit(20),
    ]);
    githubConnected = Boolean(gh?.github_installation_id);
    sourceFindings = (findings ?? []) as SourceFinding[];
  }

  const agentBrief =
    isPaid && latest
      ? buildAgentBrief(
          latest,
          fixFindings
            .filter((f) => f.source !== "scan")
            .map((f) => ({ title: f.title, severity: f.severity, consequence: f.fix }))
        )
      : null;

  if (!latest) {
    return (
      <section style={{ paddingTop: 40 }}>
        <h1 className="dxd-statement">No findings yet.</h1>
        <p className="dxd-lede" style={{ margin: "16px 0 24px" }}>
          Run your first audit and everything we find will land here, each with a fix.
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
          Open findings · what each one costs you
        </p>
        <FindingsBoard issues={issues} totalChecks={TOTAL_CHECKS} />
      </section>

      {isPaid && fixFindings.length > 0 && (
        <Reveal>
          <FixesPanel findings={fixFindings} projectRef={projectRef} />
        </Reveal>
      )}

      {isPaid && githubConfigured && (
        <Reveal>
          <GitHubPanel connected={githubConnected} findings={sourceFindings} />
        </Reveal>
      )}

      {agentBrief && (
        <section style={{ marginTop: 40 }} aria-label="AI-agent brief">
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
            For your coding agent
          </p>
          <p className="dxd-lede" style={{ marginBottom: 16 }}>
            Every open finding, formatted to hand straight to Cursor, Lovable, Bolt, or whatever
            you build in. Connect ShipLock over MCP from{" "}
            <Link href="/dashboard/settings">Settings</Link> to skip the copy-paste entirely.
          </p>
          <AgentBrief markdown={agentBrief} />
        </section>
      )}

      {!isPaid && (
        <section style={{ marginTop: 40 }}>
          <div className="dxd-connect-card">
            <div>
              <h4>Fixes are on retainer</h4>
              <p>
                You can still see what&apos;s open and what it would cost you. The fix for each —
                and the pull requests that apply them — resume the moment the retainer does.
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
