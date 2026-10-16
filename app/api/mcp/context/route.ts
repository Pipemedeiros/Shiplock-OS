import { selfCheck } from "@/lib/proof/selfCheck";
import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { deriveGuardrails } from "@/lib/guardrails/guardrails";
import { loadSecurityLoopInput } from "@/lib/agent/securityLoopData";
import { securityLoop } from "@/lib/securityLoop";
import { auditState } from "@/lib/verdict";
import { getHotRoutes } from "@/lib/traffic/hotRoutes";
import { evidenceChain, orderByChain, type ChainContext } from "@/lib/chain/evidenceChain";

// MCP `get_security_context` (Felipe 2026-09-30): what the customer's own
// agent should know before it edits a selected repository, from ShipLock's
// stored facts. Read only, PAT authenticated, no model call, no source code.
export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const repos = await getRepositories(ctx.userId);
  const named = req.nextUrl.searchParams.get("repository");
  const repo = named ? repos.find((r) => r.fullName === named) : repos.length === 1 ? repos[0] : undefined;
  if (!repo) {
    return named
      ? NextResponse.json({ error: "That repository is not selected in ShipLock." }, { status: 404 })
      : NextResponse.json({ error: "Name a repository.", repositories: repos.map((r) => r.fullName) }, { status: 400 });
  }

  const [runs, findings, source, loop, hot] = await Promise.all([getRuns(ctx.userId, 20), getOpenFindings(ctx.userId),
    loadRepositoryGraphSource(ctx.userId, repo.id), loadSecurityLoopInput(ctx.userId), getHotRoutes(ctx.userId).catch(() => ({}))]);
  // The last FINISHED audit of this repository; one still running has read
  // nothing yet and is reported as in progress, never as nothing unread.
  const { current, finished: run } = auditState(runs.filter((r) => r.fullName === repo.fullName));
  // The evidence chain per finding (lib/chain): reach from the audit's route
  // facts, pressure from attack traffic on the finding's route.
  const calledBy = new Map((run?.routeFacts ?? []).map((r) => [r.path, r.calledBy ?? []]));
  const repoHot = (hot as Record<string, { file: string; pattern: string; suspiciousRequests: number }[]>)[repo.id] ?? [];
  const chainContext = (f: { entry: string | null; file: string | null }): ChainContext => ({
    calledBy: f.entry ? calledBy.get(f.entry) : undefined, trafficConnected: loop.watch.trafficSites > 0,
    hitHard: (f.file && repoHot.find((h) => h.file === f.file)) || null,
  });
  const repoFindings = orderByChain(findings.filter((f) => f.repositoryId === repo.id).map((f) => ({ ...f, claims: f.claims ?? [] })), chainContext);

  return NextResponse.json({
    repository: repo.fullName,
    lastAudit: run ? { at: run.startedAt, status: run.status } : null,
    auditInProgress: current ? { status: current.status, step: current.trace?.at(-1)?.label ?? null } : null,
    // The same read, attack, map, fix, watch loop the dashboard shows (account wide).
    loop: securityLoop(loop).map(({ title, state, headline, detail }) => ({ stage: title, state, headline, detail })),
    stack: (run?.stack?.tools ?? []).map((t) => ({ name: t.name, kind: t.kind })),
    guardrails: source.routes ? deriveGuardrails(source.routes, { repository: repo.fullName, commit: null }) : null,
    openFindings: repoFindings.slice(0, 50)
      // confirmed: an issue proven by the agent, a replica or a live fact; false is a candidate to review (A1).
      // id and fixKind feed open_fix_pull_request (manual gets none); selfCheck is one harmless request to run on a local or preview app.
      .map((f) => ({ id: f.id, title: f.title, severity: f.severity, route: f.entry, file: f.file, consequence: f.consequence,
        confirmed: f.confirmed === true, fixKind: f.fixKind,
        selfCheck: f.entry ? selfCheck({ entry: f.entry, attackClass: f.attackClass })?.curl ?? null : null,
        // Which layers back it, and the next safe step for the agent (lib/chain/evidenceChain.ts).
        chain: (({ links, next }) => ({ links: links.map((l) => ({ link: l.id, state: l.state, evidence: l.evidence })), next }))(
          evidenceChain(f, chainContext(f))) })),
    notRead: (run?.coverage ?? []).map((c) => `${c.name}: ${c.effect}`),
    howToUse: "Keep every guardrail when you edit. Fix open findings only with the change they describe; a finding with confirmed false is a candidate to verify, not a proven issue. Anything under notRead, and any route without a rule, is not known to be safe. ShipLock's pull request check re-checks your change. To fix one, call open_fix_pull_request with its id where the customer turned agent pull requests on, or make the change in your own checkout and open the pull request yourself. Each finding's chain says which layers back it (reach, gap, proof, pressure) and its next safe step; an unknown link was not read, never cleared.",
  });
}
