import { scanPublicCredentialValues } from "@/lib/deep/clientExposure";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken } from "@/lib/deep/github";
import { fetchRepoArchive, type ArchiveFile } from "@/lib/deep/repoArchive";
import { scanSecrets } from "@/lib/deep/githubScan";
import { scanCredentialHandling } from "@/lib/deep/credentialHandling";
import { scanNextConfigEnv } from "@/lib/deep/nextConfigEnv";
import type { RouteFact } from "@/lib/graph/routeInventory";
import { proposeAttacks, riskyRoutesOmitted, routesOmitted } from "./attack";
import { claimFirstScanCredit } from "./firstScanCredit";
import { recordModelUsage } from "@/lib/cost/modelUsage";
import { crossTenantNotes, renderCrossTenantNote } from "./crossTenantNotes";
import { countUnanalyzedSurfaces } from "@/lib/graph/unanalyzedSurfaces";
import { applicationEntries } from "@/lib/graph/applicationEntries";
import { detectStack, routeAnalysisSupport, type StackReport } from "./stack";
import { buildFindings, type AgentFinding } from "./findings";
import { oneIdAccess, possessionGates } from "./possessionGate";
import { extractTables, extractColumns } from "./schema";
import { inferDomain } from "./domain";
import { loadLiveFacts } from "./liveFacts";
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
  reasoningParseFailed = false,
  unanalyzed: { serverActionFiles: number; trpcFiles: number; analyzedActions?: number; analyzedProcedures?: number } = { serverActionFiles: 0, trpcFiles: 0 },
): CoverageNote[] {
  const notes: CoverageNote[] = [];
  const routeSupport = routeAnalysisSupport(stack);

  // WHAT WE COULD NOT JUDGE, FROM THE FACTS. Leads the list, because on a real
  // codebase it is the largest single statement about this audit: on corpus-a it
  // is 139 of 442 endpoints that reach data. Computed from the route facts,
  // never from what the model happened to raise -- a disclosure conditional
  // on model behaviour is not a disclosure (lib/agent/unassessed.ts).
  const unassessed = unassessedNote(routes);
  if (unassessed) notes.push(unassessed);

  // Step 7D: data-changing code outside route handlers is not analyzed. Said
  // with the counts, because an audit that reasoned over the routes and stays
  // silent here reads as complete.
  if (unanalyzed.serverActionFiles + unanalyzed.trpcFiles > 0) {
    const actions = unanalyzed.analyzedActions ?? 0;
    const procedures = unanalyzed.analyzedProcedures ?? 0;
    const parts = [
      unanalyzed.serverActionFiles ? `${unanalyzed.serverActionFiles} ${unanalyzed.serverActionFiles === 1 ? "file defines" : "files define"} server actions` : "",
      unanalyzed.trpcFiles ? `${unanalyzed.trpcFiles} ${unanalyzed.trpcFiles === 1 ? "file defines" : "files define"} tRPC procedures` : "",
    ].filter(Boolean).join(" and ");
    const analyzedList = [
      actions ? `${actions} server ${actions === 1 ? "action" : "actions"} the browser can call` : "",
      procedures ? `${procedures} tRPC ${procedures === 1 ? "procedure" : "procedures"}` : "",
    ].filter(Boolean);
    const unread = [
      unanalyzed.serverActionFiles ? "server-only helpers" : "",
      unanalyzed.trpcFiles && !procedures ? "tRPC procedures" : "",
    ].filter(Boolean).join(" and ");
    // Step 7G: whether a router is actually served over HTTP is not traced
    // (routers often come from a workspace package we do not resolve), so
    // every procedure is treated as callable. Said, because it is an assumption.
    const analyzedPart = analyzedList.length
      ? ` ${analyzedList.join(" and ")} ${actions + procedures === 1 ? "was" : "were"} analyzed like routes${unread ? `; ${unread} were not` : ""}.` +
        (procedures ? " Every tRPC procedure was treated as reachable from the internet; which routers your app serves was not traced." : "")
      : " They can read and change data, and this audit analyzes route handlers only.";
    notes.push({
      name: "Server actions and tRPC procedures",
      why: `${parts}.${analyzedPart}`,
      effect: "Whether the paths we did not analyze check who is calling is unknown, not clean. Nothing there was reported or cleared.",
    });
  }

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
      why: "No connected provider is mapped to this repository, so we read what its code expects rather than attributing account-wide provider data to it.",
      effect:
        "A setting that exists only in a provider's dashboard is outside this audit. We can say a variable is expected, not that it is scoped correctly.",
      upgrade: "Connect and map a service from the Stack page",
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

  if (routeSupport.level === "inventory_only") {
    notes.push({
      name: "Deep route authorization analysis",
      why: routeSupport.reason,
      effect: "Framework-independent credential and configuration checks ran. Application routes and authorization paths for this framework were not assessed, so an empty route result is unknown rather than clean.",
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
      why: routeSupport.level === "inventory_only"
        ? routeSupport.reason
        : "The reasoning step did not run — either this repository took long enough to read that there was not enough time left to reason over it safely, or the reasoning call itself failed.",
      effect:
        "Committed credentials and dependency advisories were still checked. Attack paths were not looked for at all, so this run finding none means nothing.",
      ...(routeSupport.level === "deep" ? { upgrade: "Run the audit again" } : {}),
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

  if (reasoningParseFailed) {
    notes.push({
      name: "Part of this audit could not be completed",
      why: "The reasoning response was not in a readable format.",
      effect: "Any recovered findings were checked against the collected evidence, but reasoning coverage is incomplete. No findings from this step is not a clean result.",
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
  /** Durable queue-created run. When present, execution claims this row rather
   * than creating a second customer-visible run. */
  runId?: string;
  /** Queue fencing identity. Required with a queue-created runId. */
  jobLease?: { jobId: string; token: string };
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
  if (Boolean(options.runId) !== Boolean(options.jobLease)) throw new Error("Invalid durable audit context");

  // THE RUN ROW IS A PRECONDITION, NOT BOOKKEEPING.
  //
  // This used to read `(run?.id as string) ?? ""` with the insert's error
  // discarded. On a failed insert every later `.eq("id", "")` matched zero
  // rows, so the audit ran to completion writing NOTHING to audit_runs while
  // findings still persisted with a null run_id -- a dashboard showing findings
  // with no run behind them, and no error anywhere. Failing here is loud and
  // recoverable; succeeding into an empty id is silent and is not.
  const runWrite = options.runId
    ? admin.from("audit_runs").update({
        status: "running", started_at: new Date(startedAt).toISOString(), finished_at: null,
        trace: [], coverage: [], error: null,
      }).eq("id", options.runId).eq("user_id", userId).eq("repository_id", repositoryId)
        .eq("full_name", fullName).eq("audit_execution_token", options.jobLease!.token)
        .in("status", ["queued", "running", "failed"]).select("id").maybeSingle()
    : admin.from("audit_runs").insert({
        user_id: userId,
        repository_id: repositoryId,
        full_name: fullName,
        status: "running",
        trigger: options.trigger ?? "manual",
      }).select("id").single();
  const { data: run, error: runError } = await runWrite;

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
    const routeSupport = routeAnalysisSupport(stack);
    step(
      "Stack read from the code",
      stack.tools.length
        ? stack.tools.map((t) => t.name).join(" · ")
        : "no known framework, auth provider or database identified",
    );

    // Route handlers, the server actions the browser can call (7E-3) and
    // tRPC procedures (7G): one fact shape, so ranking, the prompt and the
    // guard treat them alike.
    const entries = applicationEntries(archive.files);
    const routes = entries.routes;
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
    const liveFacts = await loadLiveFacts(userId, repositoryId);
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
    const canReason = routeSupport.level === "deep" && timeLeft >= REASONING_RESERVE_MS;

    if (!canReason) {
      if (routeSupport.level === "inventory_only") {
        step("Deep route reasoning not run", routeSupport.reason);
      } else {
        step(
          "Reasoning skipped to finish inside the time budget",
          `${Math.round(elapsed / 1000)}s spent reading this repository, which leaves too little to reason safely`,
        );
      }
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

    // POSSESSION GATES REWORD A FINDING; THEY REMOVE NOTHING.
    //
    // Read after the notes and handed to the guard alone. Every route stays in
    // reasonedRoutes and the prompt is unchanged: a missing_authentication the
    // guard admits on a route whose gate we READ is reported as
    // possession_gated, at informational severity, naming the lookup, the
    // binding and the mint. An unreadable gate leaves the critical standing.
    const byPath = new Map(archive.files.map((f) => [f.path, f]));
    const gates = possessionGates(routes, byPath);
    // Q21: anonymous routes whose only way in is a random-minted id cap at WARNING.
    const oneId = oneIdAccess(routes, byPath);

    // ShipLock funds one model-assisted audit per account (3G-1). A later run
    // keeps every deterministic check; its reasoning step says it did not run.
    const funding = canReason ? await claimFirstScanCredit(userId, runId, options.jobLease) : null;
    const reasons = canReason && funding?.funded === true;
    if (reasons) step("Reasoning about who can reach what");
    const agent = reasons
      ? await proposeAttacks({
      routes: reasonedRoutes,
      stack,
      tables,
      domain,
      liveFacts,
      possessionGates: gates,
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
          skipReason: funding && !funding.funded ? funding.reason
            : routeSupport.level === "inventory_only"
            ? "the repository framework is inventory-only"
            : "not enough time left in this run",
        };

    // Q10: one cost receipt per funded model response, before anything can fail.
    if (agent.usage) {
      await recordModelUsage({ userId, purpose: "first_scan", auditRunId: runId, model: agent.usage.model,
        usage: agent.usage, stopReason: agent.usage.stopReason });
    }

    if (agent.skipped) {
      step("Attack reasoning did not run", agent.skipReason);
    } else {
      if (agent.parseFailed) {
        step("Reasoning response could not be fully read", "Recovered findings still pass the evidence guard. This run's reasoning coverage is incomplete.");
      }
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
      possessionGates: gates,
      oneIdAccess: oneId,
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
      agent.parseFailed === true,
      { ...countUnanalyzedSurfaces(archive.files), analyzedActions: entries.actions, analyzedProcedures: entries.procedures },
    );

    step("Audit complete", `${findings.length} open ${findings.length === 1 ? "path" : "paths"}`);

    const preserveExisting = agent.skipped || agent.parseFailed === true ||
      agent.truncated === true || archive.truncated || archive.skipped > 0 ||
      routes.some((route) => !route.identityReadable || !route.ownershipReadable ||
        !route.dataReadable || !route.machineGateReadable || !route.serviceRoleReadable) ||
      routesOmitted({ routes, stack, tables, domain, files: [] }) > 0 ||
      (agent.unassessed ?? []).length > 0 || (agent.unmatchedEntries ?? []).length > 0;
    if (preserveExisting) {
      step("Previous findings retained", "This run was incomplete. Earlier findings remain open until they can be reassessed.");
      coverage.push({
        name: "Previous findings remain open",
        why: "This run could not fully reassess the repository.",
        effect: "New findings were saved, but earlier findings were not marked resolved just because they were missing from this run.",
      });
    }
    await persistFindings(userId, repositoryId, runId, findings, null, preserveExisting, options.jobLease);

    // No write follows an audit. Opening a branch/PR is a separate, explicit
    // customer action through the repair endpoints. Analysis permission is not
    // repair permission, even when a fix is mechanical.

    let completeWrite = admin
      .from("audit_runs")
      .update({
        status: "complete",
        audit_execution_token: null,
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
      }).eq("id", runId);
    if (options.jobLease) completeWrite = completeWrite.eq("audit_execution_token", options.jobLease.token);
    const { data: completedRun, error: completeError } = await completeWrite.select("id").maybeSingle();

    // A run that finished but could not be MARKED finished is the stuck-in-
    // "running" spinner, and it is invisible unless we say so here.
    // A direct run keeps the historical fail-soft behavior because findings are
    // already durable. A queued run throws: its fenced retry can safely converge
    // the visible run state without letting a stale worker finalize it.
    if (completeError || (options.jobLease && !completedRun)) {
      console.error(
        `[audit] run ${runId} completed but could not be marked complete:`,
        completeError?.message ?? "work lease changed",
      );
      if (options.jobLease) throw new Error("Audit completion could not be recorded");
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

    // Direct work is marked failed and kept. Durable work returns to queued so
    // the client does not mistake a retryable attempt for a terminal result;
    // the queue marks it failed only when attempts are exhausted/permanent.
    let failWrite = admin
      .from("audit_runs")
      .update(options.jobLease
        ? { status: "queued", finished_at: null, trace,
            error: "The audit attempt stopped and will be retried." }
        : { status: "failed", audit_execution_token: null, finished_at: new Date().toISOString(), trace, error: message })
      .eq("id", runId);
    if (options.jobLease) failWrite = failWrite.eq("audit_execution_token", options.jobLease.token);
    const { error: failError } = await failWrite;

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
 * Atomically writes findings and, only after that succeeds, archives agent
 * findings from this repository that a complete run did not reproduce.
 *
 * The database RPC owns both operations and validates the tenant/repository/run
 * relationship. A failed statement rolls the entire replacement back, so a
 * partial write can never render a false-clean dashboard.
 */
export async function persistFindings(
  userId: string,
  repositoryId: string,
  runId: string,
  findings: AgentFinding[],
  client: Pick<ReturnType<typeof getSupabaseAdmin>, "rpc"> | null = null,
  preserveExisting = false,
  jobLease?: { jobId: string; token: string },
): Promise<void> {
  const { error } = await (client ?? getSupabaseAdmin()).rpc("persist_repository_findings", {
    p_user: userId, p_repository: repositoryId, p_run: runId,
    p_findings: findings, p_preserve: preserveExisting,
    p_job: jobLease?.jobId ?? null, p_token: jobLease?.token ?? null,
  });
  if (error) throw new Error("Findings could not be saved");
}
