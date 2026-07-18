import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { getLatestScan, getScanTimeline } from "@/lib/scanHistory";
import { getWatchLog, getWatchStatus } from "@/lib/monitoring/watchLog";
import { getProtectionStatus, getRecentBlocks, getRecentThreats } from "@/lib/traffic/trafficLog";
import { buildSnippet, buildWebSnippet, buildExpressSnippet } from "@/lib/traffic/snippet";
import { GUARDRAILS } from "@/lib/guardrails";
import { auditJwtSigning, type JwtSigningPosture } from "@/lib/security/sessionAudit";
import { getSupabaseAdmin } from "@/lib/supabase";
import { buildAgentBrief } from "@/lib/agentBrief";
import { env } from "@/lib/env";
import { SignOutButton } from "@/components/sign-out-button";
import { ManageBillingButton } from "@/components/d/ManageBillingButton";
import { LockMark } from "@/components/d/Brand";
import { CoverageBoard } from "@/components/d/CoverageBoard";
import { UpgradeButton } from "@/components/d/UpgradeButton";
import { AgentBrief } from "@/components/d/AgentBrief";
import { WatchPanel } from "@/components/d/WatchPanel";
import { TrafficPanel } from "@/components/d/TrafficPanel";
import { GuardrailPanel } from "@/components/d/GuardrailPanel";
import { VerifiedPanel } from "@/components/d/VerifiedPanel";
import { TwoFactorSetup } from "@/components/d/TwoFactorSetup";
import { isBetterAuthConfigured } from "@/lib/betterAuth";
import { GitHubPanel, type SourceFinding } from "@/components/d/GitHubPanel";
import { Reveal } from "@/components/d/bits";
import type { PreviewIssue, FullIssue } from "@/lib/types";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};


const TOTAL_CHECKS = 16; // lib/scanner.ts always runs the same 16 checks

export default async function DashboardPage() {
  const supabase = await getSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/auth");
  }

  // RLS-scoped read — the "users can read own profile" policy restricts
  // this to the caller's own row regardless of which auth method they used.
  const { data: profile } = await supabase
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();

  const isPaid = profile?.is_paid ?? false;
  const provider = user.app_metadata?.provider ?? "email";

  // full_issues has no SELECT grant for `authenticated`, even for the row's
  // own owner — must go through the service-role client (lib/scanHistory.ts).
  const latest = await getLatestScan(user.id);

  // Paywall filtering happens here, explicitly, mirroring
  // app/api/scan/route.ts's own pattern — never spread full_issues into
  // props when the caller isn't paid.
  const issues: (PreviewIssue | FullIssue)[] = latest
    ? (isPaid ? latest.full_issues : latest.preview_issues) ?? []
    : [];

  // Contains fix/codefix — same sensitivity as full_issues above, so only
  // ever build this when the paywall filtering already resolved to paid.
  const agentBrief = isPaid && latest ? buildAgentBrief(latest) : null;

  // Watch-panel data: counts and metadata only, nothing paywall-sensitive
  // (see lib/monitoring/watchLog.ts). The deploy-webhook URL is the one
  // exception — it's a live credential for triggering scans, so it's only
  // surfaced while the retainer is active.
  const [watchLog, watchStatus, timeline] = latest
    ? await Promise.all([getWatchLog(user.id), getWatchStatus(user.id), getScanTimeline(user.id)])
    : [[], null, []];
  const webhookUrl =
    isPaid && watchStatus?.webhookToken
      ? `${env.NEXT_PUBLIC_APP_URL}/api/monitor/vercel/${watchStatus.webhookToken}`
      : null;

  // Live traffic protection — paid only. Independent of scan findings (it's
  // about inbound traffic), so it's fetched off is_paid, not `latest`. Counts
  // and metadata only; the ingest token is a live credential, so the install
  // snippet is only built for the paid owner viewing their own dashboard.
  const [protectionStatus, trafficBlocks, trafficThreats] = isPaid
    ? await Promise.all([getProtectionStatus(user.id), getRecentBlocks(user.id), getRecentThreats(user.id)])
    : [null, [], []];
  const trafficSnippet = protectionStatus?.ingestToken
    ? buildSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
    : null;
  const trafficWebSnippet = protectionStatus?.ingestToken
    ? buildWebSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
    : "";
  const trafficExpressSnippet = protectionStatus?.ingestToken
    ? buildExpressSnippet(protectionStatus.ingestToken, env.NEXT_PUBLIC_APP_URL)
    : "";

  // Live JWT-signing posture (paid only) — externally checkable from the stored
  // project URL, no extra credential. Best-effort: on any failure it returns an
  // informational "unknown" rather than throwing.
  let jwtPosture: JwtSigningPosture | null = null;
  if (isPaid) {
    const { data: monitored } = await getSupabaseAdmin()
      .from("user_profiles")
      .select("monitored_project_url")
      .eq("id", user.id)
      .maybeSingle();
    const projectUrl = monitored?.monitored_project_url as string | null | undefined;
    if (projectUrl) jwtPosture = await auditJwtSigning(projectUrl);
  }

  // GitHub source scanning — only surfaced once the App is registered
  // (GITHUB_APP_SLUG set). Reads connection state + active source findings.
  const githubConfigured = Boolean(env.GITHUB_APP_SLUG);
  let githubConnected = false;
  let sourceFindings: SourceFinding[] = [];
  if (isPaid && githubConfigured) {
    const admin = getSupabaseAdmin();
    const [{ data: gh }, { data: findings }] = await Promise.all([
      admin.from("user_profiles").select("github_installation_id").eq("id", user.id).maybeSingle(),
      admin
        .from("deep_findings")
        .select("title, severity, consequence")
        .eq("user_id", user.id)
        .eq("source", "github")
        .is("archived_at", null)
        .order("detected_at", { ascending: false })
        .limit(20),
    ]);
    githubConnected = Boolean(gh?.github_installation_id);
    sourceFindings = (findings ?? []) as SourceFinding[];
  }

  // Verified-report share state (paid only) — service-role read, same as the
  // other per-user tokens (webhook/ingest).
  let verifiedEnabled = false;
  let verifiedToken: string | null = null;
  if (isPaid) {
    const { data: vr } = await getSupabaseAdmin()
      .from("user_profiles")
      .select("verified_report_enabled, verified_report_token")
      .eq("id", user.id)
      .maybeSingle();
    verifiedEnabled = Boolean(vr?.verified_report_enabled);
    verifiedToken = (vr?.verified_report_token as string | null) ?? null;
  }

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
              <span style={{ fontSize: 13 }}>{user.email}</span>
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

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">The coverage board</p>

            {latest ? (
              <CoverageBoard issues={issues} totalChecks={TOTAL_CHECKS} />
            ) : (
              <>
                <h1 className="dxd-statement">You haven&apos;t run an audit yet.</h1>
                <p className="dxd-lede" style={{ margin: "16px 0 24px" }}>
                  {isPaid
                    ? "Connect your Supabase project to run the first audit — findings and the fix for every issue."
                    : "Put us on retainer, then connect your Supabase project to run the first audit."}
                </p>
                <Link href="/onboarding" className="dxd-btn dxd-btn-paper">
                  {isPaid ? "Run your first audit" : "Get started"}
                </Link>
              </>
            )}
          </header>
        </div>
      </div>

      {latest && (
        <div className="dxd-shell dxd-dash-body">
          <section aria-label="Your connected stack">
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
                  <span className="dxd-stack-cat">Host</span>
                  <h3>—</h3>
                  <span className="dxd-stack-role">read-only, selected projects</span>
                </span>
                <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>
                  Coming soon
                </span>
              </div>
              <div className="dxd-stack-tile">
                <span className="dxd-stack-name">
                  <span className="dxd-stack-cat">Source</span>
                  <h3>—</h3>
                  <span className="dxd-stack-role">contents: read-only</span>
                </span>
                <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>
                  Coming soon
                </span>
              </div>
            </div>
          </section>

          {watchStatus && (
            <Reveal>
              <WatchPanel
                entries={watchLog}
                status={watchStatus}
                timeline={timeline}
                webhookUrl={webhookUrl}
              />
            </Reveal>
          )}

          {isPaid && protectionStatus && trafficSnippet && (
            <Reveal>
              <TrafficPanel
                status={protectionStatus}
                blocks={trafficBlocks}
                threats={trafficThreats}
                snippet={trafficSnippet}
                webSnippet={trafficWebSnippet}
                expressSnippet={trafficExpressSnippet}
              />
            </Reveal>
          )}

          {isPaid && githubConfigured && (
            <Reveal>
              <GitHubPanel connected={githubConnected} findings={sourceFindings} />
            </Reveal>
          )}

          {isPaid && (
            <Reveal>
              <GuardrailPanel guardrails={GUARDRAILS} jwtPosture={jwtPosture} />
            </Reveal>
          )}

          {isPaid && (
            <Reveal>
              <VerifiedPanel
                initialEnabled={verifiedEnabled}
                initialToken={verifiedToken}
                appUrl={env.NEXT_PUBLIC_APP_URL}
              />
            </Reveal>
          )}

          {/* 2FA appears only once Better Auth is configured (env vars set) —
              enrollment is opt-in, so a gated mount can never lock anyone out.
              The identity bridge + enforcement gate land in the browser-tested
              pass once configured (BETTER_AUTH.md). */}
          {isPaid && isBetterAuthConfigured() && (
            <Reveal>
              <TwoFactorSetup />
            </Reveal>
          )}

          {agentBrief && (
            <section style={{ marginTop: 40 }} aria-label="AI-agent brief">
              <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
                For your coding agent
              </p>
              <p className="dxd-lede" style={{ marginBottom: 16 }}>
                Every open finding, formatted to hand straight to Cursor, Lovable, Bolt, or
                whatever you build in.
              </p>
              <AgentBrief markdown={agentBrief} />
            </section>
          )}

          {!isPaid && (
            <section style={{ marginTop: 40 }}>
              <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
                Terms of engagement
              </p>
              <div className="dxd-connect-card">
                <div>
                  <h4>Your retainer lapsed</h4>
                  <p>
                    Fixes, SQL, copy-paste AI prompts, and the watch all pause when the
                    subscription does. Resubscribe to see this scan&apos;s findings in full and
                    pick the watch back up.
                  </p>
                </div>
                <span className="dxd-connect-cta">
                  <UpgradeButton />
                </span>
              </div>
            </section>
          )}

          <footer className="dxd-footer">
            <span className="dxd-serif" style={{ fontSize: 15 }}>
              ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
            </span>
            <span>
              last scanned{" "}
              {latest.created_at ? new Date(latest.created_at).toLocaleString() : "—"}
            </span>
          </footer>
        </div>
      )}
    </main>
  );
}
