import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getOpenFindings, getRepositories, getRuns } from "@/lib/agent/dashboardData";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { deriveGuardrails } from "@/lib/guardrails/guardrails";
import { loadSecurityLoopInput } from "@/lib/agent/securityLoopData";
import { securityLoop } from "@/lib/securityLoop";
import { auditState } from "@/lib/verdict";

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

  const [runs, findings, source, loop] = await Promise.all([getRuns(ctx.userId, 20), getOpenFindings(ctx.userId),
    loadRepositoryGraphSource(ctx.userId, repo.id), loadSecurityLoopInput(ctx.userId)]);
  // The last FINISHED audit of this repository; one still running has read
  // nothing yet and is reported as in progress, never as nothing unread.
  const { current, finished: run } = auditState(runs.filter((r) => r.fullName === repo.fullName));

  return NextResponse.json({
    repository: repo.fullName,
    lastAudit: run ? { at: run.startedAt, status: run.status } : null,
    auditInProgress: current ? { status: current.status, step: current.trace?.at(-1)?.label ?? null } : null,
    // The same read, attack, map, fix, watch loop the dashboard shows (account wide).
    loop: securityLoop(loop).map(({ title, state, headline, detail }) => ({ stage: title, state, headline, detail })),
    stack: (run?.stack?.tools ?? []).map((t) => ({ name: t.name, kind: t.kind })),
    guardrails: source.routes ? deriveGuardrails(source.routes, { repository: repo.fullName, commit: null }) : null,
    openFindings: findings.filter((f) => f.repositoryId === repo.id).slice(0, 50)
      .map((f) => ({ title: f.title, severity: f.severity, route: f.entry, file: f.file, consequence: f.consequence })),
    notRead: (run?.coverage ?? []).map((c) => `${c.name}: ${c.effect}`),
    howToUse: "Keep every guardrail when you edit. Fix open findings only with the change they describe. Anything under notRead, and any route without a rule, is not known to be safe. ShipLock's pull request check re-checks your change.",
  });
}
