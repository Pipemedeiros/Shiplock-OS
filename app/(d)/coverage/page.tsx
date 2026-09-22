import type { Metadata } from "next";
import Link from "next/link";
import { Reveal, RevealList } from "@/components/d/bits";
import { LockMark } from "@/components/d/Brand";

// What the engagement actually covers, stated at the level of detail a technical
// founder needs to evaluate it.
//
// VOICE (PRODUCT-DESIGN §13): this reader is a competent engineer who has not had
// time to own security. They are deciding whether to trust us with their
// company's data, and the thing that earns that is precision — naming the
// mechanism, the boundary and the limit — not reassurance. So: intermediate
// jargon (RLS, JWT claims, SSRF, supply chain) without a glossary, no persuasion,
// no urgency, and every limit stated where the capability is claimed rather than
// in a footnote.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Scope of engagement",
  description:
    "What ShipLock does today, read from the code that does it: a repository audit that traces who can reach which data, a merge check on pull requests, committed-secret and dependency scanning, and fix pull requests you approve. The boundaries of each are stated plainly.",
};

// EVERY CLAIM BELOW NAMES THE CODE THAT MAKES IT TRUE. Rewritten 2026-09-03
// against source. The previous version claimed sandboxed exploitation, verified
// remediation, a scheduled repository review and Postgres configuration review;
// on a GitHub-only account none of the four was true (lib/proving is imported by
// nothing outside itself; the scheduled pass runs runGithubScan and the
// monitoring collectors, not runRepositoryAudit; no account has a database
// connected). A security vendor overstating its own coverage is the failure that
// makes a buyer never come back, so where the honest statement is unflattering
// this page says the unflattering thing.
const AREAS = [
  {
    id: "01",
    name: "Repository audit",
    // lib/agent/audit.ts: fetchRepoArchive → collectRoutes → proposeAttacks →
    // attackGuard → persistFindings. Triggered by POST /api/audit and by the
    // GitHub App webhook (app/api/monitor/github/route.ts).
    lead: "We read your repository as one archive, work out which endpoints reach which tables and who can call them, and reason about how a stranger or another tenant would get to your users' data.",
    detail: [
      // lib/graph/routeInventory.ts, callPath.ts, declarations.ts.
      "Every route is traced from its exported handler through the code it actually runs: the wrappers it is passed to, the helpers it calls, the module it re-exports. From that we record whether a caller is identified, whether the query is narrowed to that caller, and which tables it touches. Evidence comes from behaviour, never from a type declaration or an import.",
      // lib/agent/attack.ts + attackGuard.ts: model proposes, guard disposes.
      "A model proposes attack paths over those facts. A deterministic guard then refuses anything that cites an endpoint, file or table we did not observe, and anything that contradicts a fact we read. What survives is reported with the reasoning, line by line, so you can disagree with it.",
      // lib/agent/unassessed.ts, wired in buildCoverage (lib/agent/audit.ts).
      "Where a check runs somewhere we could not follow, the endpoint is reported as unassessed, with the proportion and a named sample, at the top of the Coverage page. An endpoint we could not judge is never shown as clean.",
    ],
    // lib/agent/attackGuard.ts refuses on unreadable facts; lib/graph/tsconfigPaths.ts
    // resolves tsconfig paths only; workspace packages are recorded as unresolved.
    limit:
      "This is static analysis of code as written, and we do not attack your production application or anything you operate. On real codebases a large share of data-touching endpoints stays unjudged: a session resolved behind an option we did not read, an API key checked by a helper we could not classify, a query behind a workspace package we do not follow. We say so on Coverage rather than guess, and a check that could not run is recorded as not run: an absent result is never rendered as a pass. Each finding carries a stable identifier across runs, so one that flaps is not re-reported as new. The audit runs when you start it and when the GitHub App delivers a push or pull-request event; it does not run on a schedule of its own.",
  },
  {
    id: "02",
    name: "Merge check",
    // lib/agent/prCheck.ts + diffScan.ts, called from app/api/monitor/github/route.ts.
    lead: "On every pull request the GitHub App tells us about, the files it touches are checked and a verdict is posted to the pull request before the merge.",
    detail: [
      // lib/agent/diffScan.ts: committed credentials, anonymous routes reaching data,
      // routes that stop narrowing a table their siblings narrow.
      "Committed credentials in the diff, an endpoint that reaches data without identifying its caller, and an endpoint that reads a table without narrowing it to the caller when the routes beside it do. The verdict is deterministic; the model can explain a finding and can never create or clear one.",
      // diffScan.ts: `if (!route.identityReadable) continue; if (!route.ownershipReadable) continue;`
      "A route whose gate or scope we could not read never blocks a merge. The check fails closed toward passing, because a wrong block stops your pull request rather than producing a report you can argue with.",
    ],
    // Whether GitHub actually delivers the webhook is an external fact (CLAUDE.md).
    limit:
      "The check depends on the GitHub App being installed on the repository and its webhook reaching us; we cannot see that configuration from your code. Endpoints that are public by design, such as an SDK ingest route, read as anonymous and unscoped, because that is what they are; whether such a route should block a merge is a policy we have not yet let you set.",
  },
  {
    id: "03",
    name: "Source scanning",
    // lib/deep/githubRun.ts: scanSecrets, scanPublicCredentialValues,
    // scanCredentialHandling, scanNextConfigEnv,
    // scanWorkflows, scanRouteFacts (lib/graph/routeChecks.ts — C12/C13),
    // historyFindings, depFindings (OSV). Runs on the GitHub webhook and every
    // 48 hours from app/api/monitor/scheduled/route.ts.
    lead: "Deterministic checks on the source itself, on every push the App reports and at most every 48 hours from the daily pass.",
    detail: [
      "Committed and historical credentials in real key shapes, and explicit Next.js environment configuration that makes a value available for client builds. Values whose publicness is unknown are flagged for review. A publishable key in the bundle is not reported, because that is where it belongs; a service-role key is.",
      "Dependencies matched against public vulnerability advisories, and GitHub Actions workflow structure: a pull_request_target workflow that checks out the pull request's own code, a third-party action pinned to a moveable tag rather than a commit, and a workflow with no stated permissions.",
      "Two things the file settles on its own: a token or one-time code built from Math.random(), which is predictable, and a credential carried in a URL query string, where it reaches server logs, browser history and the Referer header. Under a test or scaffold path both are reported a step quieter rather than dropped.",
      "A route that changes data without identifying its caller, and mass assignment: a route that writes a request body to the database wholesale rather than a validated set of fields. These reuse the same route facts the merge check (02) reads, reported here on their own because each stands up without needing a database fact to correlate with.",
    ],
    limit:
      "A dependency advisory is matched by package and version; whether the vulnerable path is reachable in your application is not determined. Injection, cross-site scripting and weak-crypto pattern checks were withdrawn: a static per-file pattern cannot see whether a value reaching a dangerous sink is actually attacker-controlled. Reasoning about a specific route's authorization and data access, including whether client input reaches a write unscoped, still happens in the repository audit (01) with the model-hypothesis and deterministic-guard discipline described there.",
  },
  {
    id: "04",
    name: "Fix pull requests",
    // app/api/fix/pr/route.ts is a separate explicit action.
    // lib/agent/approvalBoundary.test.ts prevents audits from calling a write
    // path. lib/agent/fixPr.ts never authors authorization logic.
    lead: "After you approve a fix action, it arrives as a pull request on its own branch off your default branch. We never merge it.",
    detail: [
      "An audit only records evidence and findings. A branch or pull request is created only after you click its fix action; retries recover the same deterministic ShipLock branch or open pull request when possible.",
      "A finding closes on evidence: when a later audit no longer reproduces it, it is archived rather than waiting for someone to mark it done.",
    ],
    limit:
      "Authorisation rules, ownership checks and injection fixes are never machine-authored. Those pull requests are drafts that mark where the change belongs, for you or your coding agent to complete. A leaked credential is a rotation, and no pull request is offered for it. Nothing here demonstrates a fix by re-running an attack; there is no production proof runner today.",
  },
  {
    id: "05",
    name: "Database connection, optional and unused so far",
    // app/api/deep/supabase/* (read-only Management API OAuth, inert without
    // SUPABASE_OAUTH_CLIENT_ID), lib/deep/postgresDirect.ts (role verified
    // read-only, BEGIN TRANSACTION READ ONLY), lib/exposure/model.ts (column
    // names and row counts, never a value). No account has connected one.
    lead: "Row-level security policies live in your database, not your repository. Without a connection we infer them from code and say so; with one we read them.",
    detail: [
      "If you connect a database, configuration is read through Supabase's Management API in read-only mode or through a Postgres role we verify cannot write, inside a transaction that cannot write either. The exposure model reads column names and row counts and none of your data: never a value, never a row.",
      "What the database itself can reach: an extension able to open outbound HTTP connections and callable by a public API key, which is server-side request forgery from inside your network, and a scheduled job with a credential written into its own command text.",
      "No account has connected a database yet. Every audit to date has run on the repository alone, and every finding that depends on a policy is labelled as inferred.",
    ],
    limit:
      "We will not ask you to buy or upgrade a third-party plan to connect. Where a provider gates its configuration behind a paid tier, we read the code instead and say so.",
  },
] as const;

export default function CoveragePage() {
  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/" className="dxd-wordmark">
              <span className="dxd-wordmark-lock"><LockMark size={19} /></span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <Link href="/owasp">OWASP</Link>
              <Link href="/incidents">Incidents</Link>
              <Link href="/auth" className="dxd-btn dxd-btn-paper">Sign in</Link>
            </div>
          </nav>

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">Scope of engagement</p>
            <h1 className="dxd-statement">Four areas, and the edge of each.</h1>
            <p className="dxd-lede" style={{ margin: "18px 0 0", maxWidth: "62ch" }}>
              What follows is the whole of what we do, including where each capability stops.
              A security engagement whose limits are unstated is not one you can plan around.
            </p>
          </header>
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body">
        <RevealList>
          {AREAS.map((area) => (
            <section key={area.id} style={{ marginBottom: 52 }} aria-label={area.name}>
              <div style={{ display: "flex", gap: 14, alignItems: "baseline" }}>
                <span className="dxd-mono" style={{ fontSize: 12, color: "var(--d-bronze)" }}>{area.id}</span>
                <h2 className="dxd-serif" style={{ margin: 0, fontSize: 23 }}>{area.name}</h2>
              </div>

              <p className="dxd-lede" style={{ margin: "12px 0 18px", maxWidth: "64ch" }}>{area.lead}</p>

              <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 12 }}>
                {area.detail.map((line) => (
                  <li key={line} style={{ fontSize: 14.5, lineHeight: 1.75, color: "var(--d-muted)", maxWidth: "70ch" }}>
                    {line}
                  </li>
                ))}
              </ul>

              <div className="dxd-surface" style={{ marginTop: 18, padding: 14, maxWidth: "70ch" }}>
                <p className="dxd-mono" style={{ margin: "0 0 6px", fontSize: 11, color: "var(--d-bronze)" }}>
                  BOUNDARY
                </p>
                <p style={{ margin: 0, fontSize: 14, lineHeight: 1.75, color: "var(--d-muted)" }}>{area.limit}</p>
              </div>
            </section>
          ))}
        </RevealList>

        <Reveal>
          <section aria-label="Engagement terms" style={{ marginTop: 8 }}>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)", maxWidth: "70ch" }}>
              While the product is in its open period, any signed-in account gets everything above
              and is not charged. Billing is built and switched off; when it is switched on, the
              price will be on this page before it applies to anyone.
            </p>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)", maxWidth: "70ch", marginTop: 12 }}>
              Nothing here writes to your systems. The only thing we create is a pull request on
              your repository, and you decide whether it merges. Full terms are on the{" "}
              <Link href="/terms">terms page</Link>, and what we store is described on the{" "}
              <Link href="/privacy">privacy page</Link>.
            </p>
          </section>
        </Reveal>
      </div>
    </main>
  );
}
