import { scanPublicCredentialValues } from "@/lib/deep/clientExposure";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken } from "@/lib/deep/github";
import { fetchRepoArchive, type ArchiveFile } from "@/lib/deep/repoArchive";
import { scanSecrets } from "@/lib/deep/githubScan";
import { scanCredentialHandling } from "@/lib/deep/credentialHandling";
import { scanNextConfigEnv } from "@/lib/deep/nextConfigEnv";
import { collectRoutes, type RouteFact } from "@/lib/graph/routeInventory";
import { proposeAttacks, riskyRoutesOmitted, routesOmitted } from "./attack";
import { crossTenantNotes, renderCrossTenantNote } from "./crossTenantNotes";
import { detectStack, type StackReport } from "./stack";
import { buildFindings, type AgentFinding } from "./findings";
import { extractTables, extractColumns } from "./schema";
import { inferDomain } from "./domain";
import { loadLiveFacts } from "./liveFacts";
import { openFixPullRequests } from "./autoFixPr";
import { getOpenFindings } from "./dashboardData";
import { unassessedNote, summarizeUnassessed } from "./unassessed";

/**
 * One audit of one repository, start to finish.
 *
 * The order is Strix's: reconnaissance, then hypothesis, then validation, then
 * a report. What differs is where the attack lands. Strix runs the target and
 * exploits it; the target here belongs to a customer and is serving their
 * users, so the agent reasons against a read-only copy of the source and
 * anything reproducible is reproduced on a disposable replica instead.
 *
 * Every step appends to a trace that is stored with the run. That is not
 * logging: the trace is the product's trust device -- a customer who can read
 * what we did, line by line, can disagree with it, and a customer who cannot is
 * being asked to take a security claim on faith.
 */

export interface TraceStep {
  time: string;
  label: string;
  note?: string;
  found?: boolean;
}

export interface CoverageNote {
  name: string;
  why: string;
  effect: string;
  upgrade?: string;
}

export interface AuditResult {
  runId: string;
  findings: AgentFinding[];
  trace: TraceStep[];
  coverage: CoverageNote[];
  filesRead: number;
  entriesFound: number;
  tablesFound: number;
}

function clock(startedAt: number): string {
  const seconds = Math.floor((Date.now() - startedAt) / 1000);
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

/**
 * What this audit could NOT see. Built from what actually happened in the run,
 * never from a static list -- a coverage note that does not change when the run
 * changes is decoration.
 */
export function buildCoverage(
  stack: StackReport,
  truncated: boolean,
  skipped: number,
  hasDatabase: boolean,
  routesOmittedCount = 0,
  riskyOmittedCount = 0,
  liveProvidersRead: string[] = [],
  reasoningSkipped = false,
  reasoningTruncated = false,
  routes: RouteFact[] = [],
  wholesaleRejected = false,
  crossTenant: string[] = [],
): CoverageNote[] {
  const notes: CoverageNote[] = [];

  // WHAT WE COULD NOT JUDGE, FROM THE FACTS. Leads the list, because on a real
  // codebase it is the largest single statement about this audit: on corpus-a it
  // is 139 of 442 endpoints that reach data. Computed from the route facts,
  // never from what the model happened to raise -- a disclosure conditional
  // on model behaviour is not a disclosure (lib/agent/unassessed.ts).
  const unassessed = unassessedNote(routes);
  if (unassessed) notes.push(unassessed);

  if (!hasDatabase) {
    notes.push({
      name: "Row-level policies on your database",
      why: "We read your schema from the repository, not the policies that live inside the database.",
      effect: "Findings that depend on them stay inferred. We cannot reproduce one to prove it.",
      upgrade: "Connect a read-only database role",
    });
  }

  notes.push({
    name: "What your users actually do",
    why: "We can see which code paths exist, not which ones anyone uses.",
    effect: "We will not close anything on the assumption that nothing reads it.",
  });

  if (liveProvidersRead.length === 0) {
    notes.push({
      name: "Live configuration on your other services",
      why: "No provider is connected, so we read what your code expects rather than what your host, auth provider or payment processor actually has set.",
      effect:
        "A setting that exists only in a provider's dashboard is outside this audit. We can say a variable is expected, not that it is scoped correctly.",
      upgrade: "Connect a service from the Stack page",
    });
  }

  notes.push({
    name: "Values of your environment variables",
    why: "We read the names your code expects. We never read their values.",
    effect: "We can say a secret is missing or in the wrong place, never that it is weak.",
  });

  if (stack.authUnknown) {
    notes.push({
      name: "Your authentication provider",
      why: "We did not recognise an auth library in this repository.",
      effect: "Route identity is read from the code alone, so an unrecognised guard may read as no guard.",
    });
  }

  if (crossTenant.length > 0) {
    // An inventory statement, not a hedged finding. Every line names the file
    // and the mechanism, and says no action needed -- a maybe-finding here is a
    // critical with worse wording and costs the same trust.
    notes.push({
      name: `${crossTenant.length} gated endpoint${crossTenant.length === 1 ? "" : "s"} that read across every tenant, by design`,
      why: "These verify a shared secret or a signature before doing anything, and then process all tenants because that is what a cron or webhook does.",
      effect: crossTenant.join(" "),
    });
  }

  if (reasoningSkipped) {
    // The most important coverage note there is. A run that read the code but
    // never reasoned over it has found only what the deterministic collectors
    // find, and without saying so it is indistinguishable from a clean audit.
    notes.push({
      name: "Reasoning about who can reach what",
      // Two causes reach this note and the wording must fit both: the run ran
      // out of time to reason safely, or the reasoning call itself failed.
      // Naming only the first was accurate until `agent.skipped` started
      // routing here too.
      why: "The reasoning step did not run — either this repository took long enough to read that there was not enough time left to reason over it safely, or the reasoning call itself failed.",
      effect:
        "Committed credentials and dependency advisories were still checked. Attack paths were not looked for at all, so this run finding none means nothing.",
      upgrade: "Run the audit again",
    });
  }

  if (reasoningTruncated) {
    // Distinct from reasoningSkipped: the reasoning DID run and was cut off
    // partway through writing its answer. The findings it finished are real;
    // the ones it was still writing are gone. Without this note a partial
    // answer is indistinguishable from a complete one that found less.
    notes.push({
      name: "Some of the reasoning did not fit",
      why: "The reasoning step reached its output limit while writing this run's findings.",
      effect:
        "What is reported was completed and checked. Anything it had not finished writing is missing, so this list is a floor rather than the whole picture.",
      upgrade: "Run the audit again",
    });
  }

  if (wholesaleRejected) {
    notes.push({
      name: "This run's reasoning did not produce a usable result",
      why: "Everything the reasoning step proposed named an endpoint we could not match back to your code, so all of it was discarded.",
      effect:
        "That is a fault on our side, not a finding about your application. This run tells you nothing about attack paths either way — it is not a clean result.",
      upgrade: "Run the audit again",
    });
  }

  if (routesOmittedCount > 0) {
    // The reasoning prompt holds a bounded number of routes. Saying so is not
    // optional: an audit that silently reasoned over two thirds of a codebase
    // and reported nothing looks exactly like an audit that found nothing.
    notes.push({
      name: `${routesOmittedCount} route${routesOmittedCount === 1 ? "" : "s"} not reasoned over`,
      why: "More routes reach data than fit in one reasoning pass. We ranked them by exposure, putting routes with no identity and nothing narrowing the query first, and reasoned over that end.",
      effect:
        riskyOmittedCount > 0
          ? `${riskyOmittedCount} of them had no identity or nothing narrowing the query, so they are NOT the already-guarded ones and we did not reason over them. Treat this run as incomplete for those routes rather than clean.`
          : "The routes left out are the ones already scoped or already guarded. They are still read, and still checked for credentials and known vulnerabilities.",
    });
  }

  if (truncated || skipped > 0) {
    notes.push({
      name: `${skipped} file${skipped === 1 ? "" : "s"} we did not read`,
      why: truncated
        ? "The repository is larger than one audit's read budget."
        : "Some files were larger than we read in a single pass.",
      effect: "Anything defined only in those files is not in this report.",
    });
  }

  return notes;
}

/** Table names referenced by any route, unioned with what the schema declares. */
function tablesFrom(routes: RouteFact[], files: ArchiveFile[]): string[] {
  const fromSchema = extractTables(files);
  const fromRoutes = routes.flatMap((r) => r.tables);
  return [...new Set([...fromSchema, ...fromRoutes])].sort();
}

/**
 * How long the whole audit may take before it stops reasoning and reports.
 *
 * The route runs synchronously inside a serverless function, and this project
 * is on a plan that stops a function at 60 seconds. Being killed there is the
 * worst possible outcome: the audit_runs row is already inserted as "running",
 * so a customer with a large repository would watch a spinner forever while the
 * function that was going to finish it no longer exists.
 *
 * Ingestion and the deterministic scans are fast even on a 2,359-file monorepo,
 * about four seconds of compute. What varies is the tarball download and the
 * model call. So the budget is spent where it can be given up: if there is not
 * enough time left to reason, the run completes with what the deterministic
 * collectors found and says on the Coverage page that reasoning was skipped.
 * A shorter honest audit beats a run that never finishes.
 */
export const AUDIT_BUDGET_MS = 50_000;
/** Reasoning needs roughly this long, measured across real repositories. */
export const REASONING_RESERVE_MS = 25_000;

export interface RunAuditOptions {
  userId: string;
  installationId: number;
  repositoryId: string;
  fullName: string;
  trigger?: string;
  /** True when this account also has a database connected. Changes coverage. */
  hasDatabase?: boolean;
}

/**
 * Runs an audit and records it.
 *
 * A failure is written to the run with its trace intact rather than thrown
 * away: a failed audit the customer can read is worth more than a silent one,
 * and it is the only way "the audit did not finish" stays distinguishable from
 * "the audit found nothing".
 */
export async function runRepositoryAudit(options: RunAuditOptions): Promise<AuditResult> {
  const { userId, installationId, repositoryId, fullName } = options;
  const admin = getSupabaseAdmin();
  const startedAt = Date.now();
  const trace: TraceStep[] = [];
  const step = (label: string, note?: string, found?: boolean) => {
    trace.push({ time: clock(startedAt), label, ...(note ? { note } : {}), ...(found ? { found } : {}) });
  };

  // THE RUN ROW IS A PRECONDITION, NOT BOOKKEEPING.
  //
  // This used to read `(run?.id as string) ?? ""` with the insert's error
  // discarded. On a failed insert every later `.eq("id", "")` matched zero
  // rows, so the audit ran to completion writing NOTHING to audit_runs while
  // findings still persisted with a null run_id -- a dashboard showing findings
  // with no run behind them, and no error anywhere. Failing here is loud and
  // recoverable; succeeding into an empty id is silent and is not.
  const { data: run, error: runError } = await admin
    .from("audit_runs")
    .insert({
      user_id: userId,
      repository_id: repositoryId,
      full_name: fullName,
      status: "running",
      trigger: options.trigger ?? "manual",
    })
    .select("id")
    .single();

  if (runError || !run?.id) {
    // Thrown before any work begins, so there is nothing to roll back and no
    // partial state to explain.
    throw new Error(
      `Could not start the audit: ${runError?.message ?? "the run could not be recorded"}`,
    );
  }

  const runId = run.id as string;

  try {
    step(`Read-only checkout of ${fullName}`);

    const token = await getInstallationToken(installationId);
    const archive = await fetchRepoArchive(token, fullName);
    step(
      `${archive.files.length} files read`,
      `${Math.round(archive.bytesRead / 1024)} KB of source${archive.skipped ? `, ${archive.skipped} skipped` : ""}`,
    );

    const stack = detectStack(archive.files);
    step(
      "Stack read from the code",
      stack.tools.length
        ? stack.tools.map((t) => t.name).join(" · ")
        : "no known framework, auth provider or database identified",
    );

    const routes = collectRoutes(archive.files);
    const withData = routes.filter((r) => r.tables.length > 0);
    step(
      `${routes.length} application entries mapped`,
      `${routes.filter((r) => r.authenticated).length} require a user · ${routes.filter((r) => r.machineGated).length} machine-gated · ${routes.filter((r) => !r.authenticated && !r.machineGated).length} anonymous`,
    );

    const tables = tablesFrom(routes, archive.files);
    step(`${tables.length} tables found`, `${withData.length} entries reach one`);

    // Deterministic detectors first. These do not need a model, they do not
    // fail open, and their findings are the ones the agent's hypotheses are
    // judged against.
    const repoFiles = archive.files.map((f) => ({ path: f.path, content: f.content }));
    const deterministic = [
      ...scanSecrets(repoFiles),
      ...scanNextConfigEnv(repoFiles),
      ...scanPublicCredentialValues(repoFiles),
      ...scanCredentialHandling(repoFiles),
    ];
    if (deterministic.length > 0) {
      step(`${deterministic.length} committed credential or configuration-exposure issue${deterministic.length === 1 ? "" : "s"}`, undefined, true);
    } else {
      step("No committed credentials found");
    }

    // What the business IS, before asking what can go wrong with it. A model
    // asked "find bugs in these routes" produces a linter; a model told "rows
    // are separated by workspace_id" produces hypotheses about this customer's
    // actual risk.
    // The live half. Facts a provider reported about itself, which the
    // repository cannot show. Absent when nothing is connected, and absent is
    // the honest state: the audit runs on the code alone and says so.
    const liveFacts = await loadLiveFacts(userId);
    if (liveFacts.length > 0) {
      step(
        `${liveFacts.length} live configuration fact${liveFacts.length === 1 ? "" : "s"} from your connected services`,
        liveFacts
          .slice(0, 3)
          .map((f) => f.statement)
          .join(" · "),
      );
    }

    const domain = inferDomain(tables, routes, extractColumns(archive.files));
    step(
      "Business model read from the schema",
      domain.summary,
    );

    const elapsed = Date.now() - startedAt;
    const timeLeft = AUDIT_BUDGET_MS - elapsed;
    const canReason = timeLeft >= REASONING_RESERVE_MS;

    if (!canReason) {
      step(
        "Reasoning skipped to finish inside the time budget",
        `${Math.round(elapsed / 1000)}s spent reading this repository, which leaves too little to reason safely`,
      );
    }

    // CROSS-TENANT MACHINE-GATED ENDPOINTS BECOME NOTES, NOT CANDIDATES.
    //
    // A cron or webhook that verifies a shared secret and then reads every
    // tenant is doing its job. Emitted only where the gate was READ -- named
    // file, named mechanism, and never where the check sits behind a
    // process.env comparison, because on a self-hosted deployment that gate
    // does not run and the note would be a confident instruction not to look.
    // Everything else in population A stays a candidate.
    const notes = crossTenantNotes(routes, new Map(archive.files.map((f) => [f.path, f])));
    const noted = new Set(notes.map((n) => n.path));
    const reasonedRoutes = routes.filter((r) => !noted.has(r.path));

    if (canReason) step("Reasoning about who can reach what");
    const agent = canReason
      ? await proposeAttacks({
      routes: reasonedRoutes,
      stack,
      tables,
      domain,
      liveFacts,
      files: archive.files.map((f) => f.path),
      // Whatever is left of the budget, less a margin to persist the findings
      // and finish the run. Reasoning is the step we give up, so it is the step
      // that gets bounded.
      timeoutMs: Math.max(5_000, AUDIT_BUDGET_MS - (Date.now() - startedAt) - 6_000),
        })
      : {
          admitted: [],
          rejected: [],
          unassessed: [],
          unmatchedEntries: [],
          model: "none",
          skipped: true,
          skipReason: "not enough time left in this run",
        };

    if (agent.skipped) {
      step("Attack reasoning did not run", agent.skipReason);
    } else {
      if (agent.truncated) {
        step(
          "Reasoning hit its output limit",
          "The findings below were completed and checked; anything still being written is missing from this run.",
        );
      }
      // A RUN WHERE EVERYTHING WAS THROWN AWAY IS NOT A CLEAN RUN.
      // The model named routes and we could not match a single one, which means
      // the audit produced nothing for a reason that has nothing to do with the
      // customer's code. Said loudly, because for four measurement stages this
      // rendered as "0 attack paths" and was indistinguishable from a repository
      // with no attack paths in it.
      if (agent.admitted.length === 0 && (agent.unmatchedEntries ?? []).length > 0) {
        step(
          "This run's reasoning was discarded",
          `Every proposed finding named an endpoint we could not match (${agent.unmatchedEntries.slice(0, 3).join(", ")}). This is a fault on our side, not a result about your code.`,
        );
      }
      if ((agent.unassessed ?? []).length > 0) {
        step(
          `${agent.unassessed.length} endpoint${agent.unassessed.length === 1 ? "" : "s"} left unjudged`,
          "A possible problem was proposed on these and dropped: the check that decides who may see the data runs somewhere we could not follow.",
        );
      }
      step(
        `${agent.admitted.length} attack ${agent.admitted.length === 1 ? "path" : "paths"} proposed and checked`,
        agent.rejected.length
          ? `${agent.rejected.length} discarded for citing something we did not observe`
          : undefined,
        agent.admitted.length > 0,
      );
    }

    const findings = buildFindings({
      admitted: agent.admitted,
      deterministic,
      routes,
      stack,
      repositoryId,
      hasDatabase: options.hasDatabase ?? false,
      liveFacts,
    });

    for (const finding of findings.filter((f) => f.severity === "CRITICAL")) {
      step(finding.title, finding.consequence, true);
    }

    const coverage = buildCoverage(
      stack,
      archive.truncated,
      archive.skipped,
      options.hasDatabase ?? false,
      routesOmitted({ routes, stack, tables, domain, files: [] }),
      riskyRoutesOmitted({ routes, stack, tables, domain, files: [] }),
      liveFacts.length > 0 ? ["connected"] : [],
      // A model call that FAILED is a skipped reasoning step, exactly like one
      // we never had time to start. This used to pass `!canReason` alone -- the
      // time-budget check -- so a 400 from the API produced an audit with zero
      // reasoned findings, no coverage note, and nothing distinguishing it from
      // a clean result. Ten such calls were mistaken for ten measured zeros on
      // 2026-09-08 before the discipline of diagnosing every zero caught it.
      !canReason || agent.skipped === true,
      agent.truncated === true,
      routes,
      agent.admitted.length === 0 && (agent.unmatchedEntries ?? []).length > 0,
      notes.map(renderCrossTenantNote),
    );

    step("Audit complete", `${findings.length} open ${findings.length === 1 ? "path" : "paths"}`);

    await persistFindings(userId, repositoryId, runId, findings);

    // Open the pull requests ourselves. The customer's job is to approve, not
    // to go and press a button per finding -- a queue of security homework is
    // the thing this product exists not to be.
    //
    // Deliberately AFTER persistFindings and deliberately wrapped: the findings
    // are the audit's value and they are already safely written. If GitHub is
    // down, or the App lost access to the repository, the run still completes
    // and the dashboard still offers the same pull request on one click.
    let prsOpened = 0;
    try {
      const open = await getOpenFindings(userId);
      const outcome = await openFixPullRequests(
        userId,
        open.filter((f) => f.repository === fullName),
      );
      prsOpened = outcome.opened.length;
      if (prsOpened > 0) {
        step(
          `${prsOpened} fix pull request${prsOpened === 1 ? "" : "s"} opened for your approval`,
          outcome.opened.map((o) => `#${o.number ?? "?"}`).join(" · "),
        );
      }
      if (outcome.failed.length > 0) {
        step(
          `${outcome.failed.length} fix pull request${outcome.failed.length === 1 ? "" : "s"} could not be opened`,
          outcome.failed[0].error,
        );
      }
    } catch (err) {
      step("Fix pull requests could not be opened", err instanceof Error ? err.message : "unknown error");
    }

    const { error: completeError } = await admin
      .from("audit_runs")
      .update({
        status: "complete",
        finished_at: new Date().toISOString(),
        trace,
        coverage,
        files_read: archive.files.length,
        // The numbers behind the coverage note, kept as data so the Verified
        // report does not have to parse them out of a sentence.
        unassessed: summarizeUnassessed(routes),
        entries_found: routes.length,
        tables_found: tables.length,
        findings_count: findings.length,
        // Stored with the run, so the dashboard shows the stack we REASONED
        // OVER rather than a fresh guess made at page-load time.
        stack,
        domain,
      })
      .eq("id", runId);

    // A run that finished but could not be MARKED finished is the stuck-in-
    // "running" spinner, and it is invisible unless we say so here.
    // Logged, NOT thrown. The findings are already persisted and correct;
    // throwing here would fall into the catch below and mark a successful audit
    // "failed", which contradicts the rows we just wrote. What is left is a run
    // stuck on "running" with its results intact -- a monitoring problem, and
    // now a visible one rather than a silent one.
    if (completeError) {
      console.error(
        `[audit] run ${runId} completed but could not be marked complete:`,
        completeError.message,
      );
    }

    const { error: repoError } = await admin
      .from("repositories")
      .update({ last_audit_at: new Date().toISOString() })
      .eq("id", repositoryId);

    // Not fatal: the audit and its findings are already written, and a stale
    // last_audit_at costs a scheduling decision, not a result. Logged so it is
    // not invisible.
    if (repoError) {
      console.error(`[audit] could not stamp last_audit_at for ${repositoryId}:`, repoError.message);
    }

    return {
      runId,
      findings,
      trace,
      coverage,
      filesRead: archive.files.length,
      entriesFound: routes.length,
      tablesFound: tables.length,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : "unknown error";
    step("Audit failed", message);

    // The run is marked failed and KEPT. Nothing is archived and no findings are
    // written, so a broken run can never resolve a real finding by omission.
    const { error: failError } = await admin
      .from("audit_runs")
      .update({ status: "failed", finished_at: new Date().toISOString(), trace, error: message })
      .eq("id", runId);

    // Both halves matter and only one is recoverable, so both are logged: the
    // original failure is what the customer needs, and a failure to RECORD the
    // failure is what leaves the row on "running" forever.
    if (failError) {
      console.error(`[audit] run ${runId} failed AND could not be marked failed:`, failError.message);
    }

    throw err;
  }
}

/**
 * Writes findings, archiving anything from a previous run on this repository
 * that no longer reproduces.
 *
 * Archiving happens only after a SUCCESSFUL run reaches this point -- the
 * caller's catch never gets here -- so a failed audit cannot mark a customer's
 * real problems as resolved.
 */
export async function persistFindings(
  userId: string,
  repositoryId: string,
  runId: string,
  findings: AgentFinding[],
  client: { from: (t: string) => never } | null = null,
): Promise<void> {
  const admin = (client ?? getSupabaseAdmin()) as ReturnType<typeof getSupabaseAdmin>;
  const activeIds = findings.map((f) => f.id);

  // ── 1. INSERT FIRST. ────────────────────────────────────────────────────
  //
  // The order is the whole fix. This used to archive first and insert second,
  // and a death between the two left the previous findings archived with
  // nothing written in their place -- a dashboard showing ZERO, which reads as
  // clean. Inverting it means a crash here leaves the OLD findings intact and
  // simply adds nothing: too much or unchanged, never absent.
  //
  // `upsert` with ignoreDuplicates makes the statement re-runnable against
  // migration 051's partial unique index, so a retry after a partial write
  // converges instead of duplicating.
  if (findings.length > 0) {
    const { error: insertError } = await admin
      .from("deep_findings")
      .upsert(
        findings.map((f) => ({
          user_id: userId,
          repository_id: repositoryId,
          run_id: runId || null,
          source: "agent",
          finding_id: f.id,
          severity: f.severity,
          title: f.title,
          consequence: f.consequence,
          attack_class: f.attackClass,
          entry: f.entry,
          file: f.file,
          confidence: f.confidence,
          fix_kind: f.fixKind,
          claims: f.claims,
          blast_radius: f.blastRadius,
        })),
        { onConflict: "repository_id,finding_id", ignoreDuplicates: true },
      );

    // Checked, where both writes previously discarded their error. If the
    // insert failed we must NOT proceed to archive -- archiving on the strength
    // of a run whose findings were never written is exactly the zero-findings
    // failure, arrived at by a different route.
    if (insertError) {
      throw new Error(`Findings could not be saved: ${insertError.message}`);
    }
  }

  // ── 2. ARCHIVE SECOND, keyed on what this run reproduced. ───────────────
  //
  // Anything still open for this repository that this run did not produce is
  // resolved. Reached only after the insert succeeded, so the replacement set
  // is already durable before anything is retired.
  const archive = admin
    .from("deep_findings")
    .update({ archived_at: new Date().toISOString() })
    .eq("repository_id", repositoryId)
    .is("archived_at", null);

  const { error: archiveError } = await (activeIds.length > 0
    ? archive.not("finding_id", "in", `(${activeIds.map((id) => `"${id}"`).join(",")})`)
    : archive);

  // Not thrown. The new findings are written and correct; failing here leaves
  // stale rows visible alongside them, which is the safe direction and self-
  // corrects on the next successful run.
  if (archiveError) {
    console.error(
      `[audit] findings for ${repositoryId} were written but stale ones could not be archived:`,
      archiveError.message,
    );
  }
}
