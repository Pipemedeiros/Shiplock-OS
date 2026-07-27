import type { Metadata } from "next";
import Link from "next/link";
import { LockMark } from "@/components/d/Brand";
import { CoverageBoard } from "@/components/d/CoverageBoard";
import { WatchPanel } from "@/components/d/WatchPanel";
import { TrafficPanel } from "@/components/d/TrafficPanel";
import { GuardrailPanel } from "@/components/d/GuardrailPanel";
import { GitHubPanel, type SourceFinding } from "@/components/d/GitHubPanel";
import { VerifiedPanel } from "@/components/d/VerifiedPanel";
import { FixesPanel } from "@/components/d/FixesPanel";
import { McpPanel } from "@/components/d/McpPanel";
import { AgentBrief } from "@/components/d/AgentBrief";
import { Reveal } from "@/components/d/bits";
import { GUARDRAILS } from "@/lib/guardrails";
import { buildAgentBrief } from "@/lib/agentBrief";
import type { FullIssue, PreviewIssue, BlockedSource, ProtectionStatus } from "@/lib/types";
import type { FixableFinding } from "@/lib/fixes/lane";
import type { JwtSigningPosture } from "@/lib/security/sessionAudit";

// PUBLIC visual preview of the CURRENT dashboard — the real panels rendered with
// mock data, no auth. For reviewing the UI only; the action buttons call real
// (unauthenticated) APIs and will error harmlessly. Not linked from the product.
export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Dashboard preview (mock)", robots: { index: false } };

const TOTAL_CHECKS = 16;
const now = Date.now();
const iso = (minsAgo: number) => new Date(now - minsAgo * 60_000).toISOString();

const FULL_ISSUES: FullIssue[] = [
  {
    title: "The invoices table has no row-level security", severity: "CRITICAL",
    consequence: "Anyone with your public key can read every invoice — names, amounts, emails.",
    fix: "Run in Supabase SQL Editor:\nALTER TABLE invoices ENABLE ROW LEVEL SECURITY;\nCREATE POLICY owner_only ON invoices USING (auth.uid() = user_id);",
    codefix: { file: "supabase/migrations/fix.sql", description: "Enable RLS + owner policy", prompt: "Enable RLS on invoices and add an owner-only policy." },
  },
  {
    title: "Login endpoint has no rate limit", severity: "WARNING",
    consequence: "Attackers can brute-force passwords against /auth/v1/token unthrottled.",
    fix: "Add rate limiting at your edge, or enable Supabase Auth's built-in protections.",
  },
  {
    title: "Detailed database errors are returned to the client", severity: "WARNING",
    consequence: "Error responses leak schema details useful to an attacker.",
    fix: "Return generic errors from your API layer; don't surface raw PostgREST errors.",
  },
  {
    title: "HTTPS is enforced", severity: "INFO", consequence: "Traffic is encrypted in transit.", fix: "No action needed.",
  },
];
const issues: (PreviewIssue | FullIssue)[] = FULL_ISSUES;

const fixFindings: FixableFinding[] = [
  { id: "scan:invoices-no-rls", source: "scan", title: "invoices — no row-level security", severity: "CRITICAL", fix: FULL_ISSUES[0].fix, filePath: "supabase/migrations/fix.sql" },
  { id: "policy:public.orders:p:unrestricted_read", source: "policy", title: "RLS policy on orders exposes every row", severity: "CRITICAL", fix: "The USING clause is `true`, so any visitor can read every row. Scope it: USING (auth.uid() = user_id)." },
  { id: "acme/app::github:injection:sql_injection:api/search.ts", source: "github", title: "Possible SQL injection in api/search.ts", severity: "CRITICAL", fix: "Query is built by string interpolation. Use parameterized queries ($1 placeholders).", filePath: "api/search.ts" },
  { id: "exposed:git_exposed", source: "github", title: "Your Git repository is publicly served", severity: "CRITICAL", fix: "Your .git directory is reachable over the web, exposing your source history. Block /.git at your host." },
];

const sourceFindings: SourceFinding[] = [
  { title: "lodash@4.17.11 — CVE-2021-23337", severity: "WARNING", consequence: "Command injection via template. Update lodash past the vulnerable version." },
  { title: "Auth session stored in localStorage (XSS can steal it)", severity: "WARNING", consequence: "Move to the cookie-based @supabase/ssr client." },
];

const protectionStatus: ProtectionStatus = { installed: true, lastSeenAt: iso(3), activeBlocks: 2, ingestToken: "demo_ingest_token" };
const trafficBlocks: BlockedSource[] = [
  { sourceId: "a1b2c3", reason: "Credential stuffing — 40 auth attempts in 60s", severity: "CRITICAL", blockedAt: iso(22), expiresAt: iso(-1400) },
  { sourceId: "d4e5f6", reason: "Endpoint scanning — 8 distinct paths", severity: "WARNING", blockedAt: iso(90), expiresAt: iso(-1300) },
];

const jwtPosture: JwtSigningPosture = {
  severity: "INFO", ok: true, title: "Session tokens are asymmetrically signed",
  detail: "Your project publishes asymmetric JWT signing keys — sessions can't be forged without the private key. This is the safe configuration.",
};

const agentBrief = buildAgentBrief(
  { issue_count: FULL_ISSUES.length, preview_issues: null, full_issues: FULL_ISSUES, created_at: iso(30), project_url_hash: "hash_demo_abc123" },
  fixFindings.filter((f) => f.source !== "scan").map((f) => ({ title: f.title, severity: f.severity, consequence: f.fix }))
);

export default function DashboardDemoPage() {
  return (
    <main className="dxd">
      <div style={{ background: "var(--d-bronze)", color: "#fff", textAlign: "center", padding: "8px 16px", fontSize: 12.5 }} className="dxd-mono">
        Preview · mock data — this is the current dashboard UI (buttons are inert here).
      </div>

      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/" className="dxd-wordmark">
              <span className="dxd-wordmark-lock"><LockMark size={19} /></span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <span className="dxd-mono" style={{ fontSize: 12, color: "var(--d-muted-light)" }}>project ...abc123</span>
              <span style={{ fontSize: 13 }}>founder@yourapp.com</span>
              <span className="dxd-mono" style={{ fontSize: 11 }}>Pro</span>
            </div>
          </nav>

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">The coverage board</p>
            <CoverageBoard issues={issues} totalChecks={TOTAL_CHECKS} />
          </header>
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body">
        <section aria-label="Your connected stack">
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>Your stack · what the watch can see</p>
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
              <span className="dxd-stack-status dxd-chip dxd-chip-verified">Connected</span>
            </div>
          </div>
        </section>

        <Reveal>
          <WatchPanel
            entries={[
              // NOTE: there is no "github_pr" trigger to show here — per-PR source
              // scans write to deep_findings and never create a monitoring_snapshot,
              // so they don't appear in the watch log at all. See SCAN-ECONOMICS.md §5.
              { trigger: "scheduled_48h", createdAt: iso(30), findingCount: 4, criticalCount: 1, newCount: 0 },
              { trigger: "hourly", createdAt: iso(90), findingCount: 4, criticalCount: 1, newCount: null },
              { trigger: "scheduled_48h", createdAt: iso(600), findingCount: 5, criticalCount: 2, newCount: 1 },
            ]}
            status={{ enabled: true, webhookToken: "demo_webhook", lastDeepScanAt: iso(600) }}
            timeline={[
              { issue_count: 4, created_at: iso(30) },
              { issue_count: 4, created_at: iso(90) },
              { issue_count: 5, created_at: iso(600) },
              { issue_count: 7, created_at: iso(3000) },
            ]}
          />
        </Reveal>

        <Reveal>
          <TrafficPanel
            status={protectionStatus}
            blocks={trafficBlocks}
            threats={[{ reason: "One session seen from 5 sources — possible hijack", alertedAt: iso(50) }]}
            snippet={"// middleware.ts — ShipLock traffic protection (demo)\nexport { shiplock as middleware } from '@shiplock/edge';"}
            webSnippet={"import { shiplockGuard } from '@shiplock/edge';\nawait shiplockGuard(request);"}
            expressSnippet={"app.use(require('@shiplock/edge').express('demo_token'));"}
          />
        </Reveal>

        <Reveal>
          <GitHubPanel connected={true} findings={sourceFindings} />
        </Reveal>

        <Reveal>
          <GuardrailPanel guardrails={GUARDRAILS} jwtPosture={jwtPosture} />
        </Reveal>

        <Reveal>
          <VerifiedPanel initialEnabled={true} initialToken="demo_verified_token" appUrl="https://shiplock.dev" />
        </Reveal>

        <Reveal>
          <FixesPanel findings={fixFindings} projectRef="demo_project_ref" />
        </Reveal>

        <Reveal>
          <McpPanel initialTokens={[{ id: "1", name: "MCP token", created_at: iso(200), last_used_at: iso(5) }]} />
        </Reveal>

        <section style={{ marginTop: 40 }} aria-label="AI-agent brief">
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>For your coding agent</p>
          <p className="dxd-lede" style={{ marginBottom: 16 }}>
            Every open finding, formatted to hand straight to Cursor, Lovable, Bolt, or whatever you build in.
          </p>
          <AgentBrief markdown={agentBrief} />
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span></span>
          <span>last scanned {new Date(iso(30)).toLocaleString()}</span>
        </footer>
      </div>
    </main>
  );
}
