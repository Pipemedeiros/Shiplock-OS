import { getSupabaseAdmin } from "@/lib/supabase";
import { findAttackPaths } from "./attackPaths";
import { generateNarratives } from "./narrative";
import type { GraphInput } from "./graph";
import type { RouteFact } from "./routeInventory";
import type { ReachabilityIndex } from "./reachability";
import type { TableInventory } from "@/lib/exposure/model";
import { loadRepositoryReachability, loadRepositoryGraphSource } from "./repositorySource";
import { loadCurrentDatabaseEvidence } from "./databaseSource";
import { loadRepositoryDatabaseEvidence, projectRepositoryDatabaseEvidence } from "./repositoryDatabase";
import { collectTrafficFacts } from "@/lib/traffic/graphFacts";

// Persistence and execution for the reasoner.
//
// Collectors run on different triggers — source per pull request, database on the
// 48h pass, traffic continuously — so each writes its facts here and the reasoner
// reads whatever is current. Without this, correlation would depend on which
// trigger happened to fire last, and paths would appear and vanish for reasons
// that have nothing to do with the customer's security.

export type Collector = "source" | "db" | "traffic" | "runtime";

export interface FactObservation {
  /** When this field was recorded, not the provider's last-change time. */
  recordedAt: string;
  completeness: "complete" | "partial" | "unknown";
  reason?: string;
}

interface FactMetadata {
  version: 1;
  fields: Record<string, FactObservation>;
}

function previousMetadata(facts: Record<string, unknown>): FactMetadata {
  const metadata = facts._evidence as Partial<FactMetadata> | undefined;
  if (metadata?.version !== 1 || !metadata.fields || typeof metadata.fields !== "object") {
    return { version: 1, fields: {} };
  }
  return { version: 1, fields: { ...metadata.fields } };
}

export interface SourceFacts {
  routes: RouteFact[];
  /** Additive provenance; legacy flat fields remain until scoped consumers ship. */
  repositories?: RepositorySourceSnapshot[];
  /**
   * Files reachable from an entry point, computed at scan time because that is
   * the only moment the repo contents are in memory. Storing the verdict rather
   * than the corpus keeps this to a few hundred strings instead of megabytes.
   */
  liveFiles?: string[];
  hasEntryPoints?: boolean;
  /**
   * The dependency inventory, kept so new CVEs can be checked against it on a
   * schedule rather than only when the customer happens to push.
   */
  dependencies?: { name: string; version: string }[];
}

/** GitHub-issued identity, not yet a selected ShipLock-repository association. */
export interface RepositorySourceSnapshot {
  /** ShipLock tenant-bound repository identity. New fenced producers include it. */
  repositoryId?: string;
  /** GitHub-issued immutable repository identity when the installation reports it. */
  providerRepositoryId?: string;
  repositoryFullName: string;
  installationId: string;
  /** Mutable branch name, not a claim that a particular commit was read/deployed. */
  ref: string;
  recordedAt: string;
  completeness: "partial";
  filesAttempted: number;
  filesRead: number;
  routes: RouteFact[];
  liveFiles: string[];
  hasEntryPoints: boolean;
  dependencies: { name: string; version: string }[];
}

/** Transport-local observation; connection provenance is not a repository link. */
export interface DirectPostgresSnapshot {
  collector: "postgres-direct";
  authzProvider: "postgres-rls";
  /** SHA-256 of stored ciphertext, never a DSN/password/host or plaintext hash. */
  connectionFingerprint: string;
  recordedAt: string;
  /** Successful catalogue queries do not establish full application coverage. */
  completeness: "unknown";
  policies: NonNullable<GraphInput["policies"]>;
  scanTables: { name: string; rlsEnabled: boolean }[];
}

/** Management facts, without loose auth configuration or inferred repo links. */
export interface SupabaseManagementSnapshot {
  collector: "supabase-management";
  authzProvider: "postgres-rls";
  projectRef: string;
  /** Credential-instance identity, not an immutable OAuth connection epoch. */
  connectionFingerprint: string;
  recordedAt: string;
  completeness: "unknown";
  policies: NonNullable<GraphInput["policies"]>;
  /** Omitted means this pass could not read advisors; [] means read and empty. */
  advisors?: NonNullable<GraphInput["advisors"]>;
  /** Only the two boolean flags used by readAuthPosture, never loose config. */
  authConfig: { disable_signup?: boolean; mailer_autoconfirm?: boolean } | null;
}

/** Endpoint scanner output, not proof of database controls or a repository link. */
export interface SupabaseEndpointSnapshot {
  collector: "supabase-scan";
  authzProvider: "postgres-rls";
  endpointUrl: string;
  /** Parsed from the validated input hostname, not a provider-issued binding. */
  projectRef: string;
  identitySource: "validated-input";
  connectionFingerprint: string;
  recordedAt: string;
  completeness: "unknown";
  /** Whether RLS state was observed for none, some, or all enumerated tables. */
  rlsReadability: "unknown" | "partial" | "complete";
  tableReports: { name: string; rlsEnabled: boolean; rlsReadable: boolean }[];
}

export interface DbFacts {
  /** Self-contained direct transport facts; never filled from flat merged JSON. */
  directPostgresSnapshot?: DirectPostgresSnapshot;
  supabaseManagementSnapshot?: SupabaseManagementSnapshot;
  supabaseEndpointSnapshot?: SupabaseEndpointSnapshot;
  /**
   * Which authorization engine these facts came from. Written by the collector
   * rather than inferred downstream, so a future non-Postgres collector cannot
   * be silently misread as Postgres. Absent on rows written before this existed,
   * which `observedProvider` handles by inferring.
   */
  authzProvider?: GraphInput["authzProvider"];
  scanTables: { name: string; rlsEnabled: boolean }[];
  /** A21 PII inventory — schema only, never values. */
  inventory?: TableInventory[];
  policies: GraphInput["policies"];
  advisors: GraphInput["advisors"];
  authConfig: GraphInput["authConfig"];
}

export interface TrafficFacts {
  hotPaths: { path: string; suspiciousRequests: number }[];
}

/**
 * Live provider configuration, read through an API rather than from the repo.
 *
 * `providersRead` is the load-bearing field and the reason this is not just a
 * list. It names the providers we actually reached this pass. Without it,
 * "we called Vercel and it reported nothing wrong" and "we never called Vercel"
 * both arrive as an empty array, and the reasoner reads absence as good news.
 * That is precisely the `rulesRead` bug this repository already shipped once,
 * where a table with RLS on and policies unread reported as protected.
 */
export interface RuntimeFacts {
  /** Provider ids we successfully read this pass. Presence, not emptiness. */
  providersRead: string[];
  /**
   * Environment variables the host reports, by NAME and scope only. Never a
   * value: "ShipLock never reads your users' data" covers their secrets too.
   */
  envVars?: GraphInput["runtimeEnvVars"];
}

/**
 * Upsert one collector's facts. Fail-soft: never break the pass that calls it.
 *
 * `merge` exists because the `db` collector has TWO independent producers on
 * different schedules: the Management API scan supplies policies, advisors and
 * auth config, while the 16-check scan supplies per-table RLS state. A plain
 * upsert would let whichever ran last erase the other's facts, and the reasoner
 * would then see a project with policies but no tables (or the reverse) and
 * quietly stop producing paths. Partial writers must merge.
 */
export async function saveFacts(
  userId: string,
  collector: Collector,
  facts: Partial<SourceFacts & DbFacts & TrafficFacts & RuntimeFacts>,
  options: { merge?: boolean; completeness?: FactObservation["completeness"]; reason?: string } = {}
): Promise<void> {
  try {
    const admin = getSupabaseAdmin();
    const recordedAt = new Date().toISOString();
    let next: Record<string, unknown> = { ...facts };
    let metadata: FactMetadata = { version: 1, fields: {} };

    if (options.merge) {
      const { data, error } = await admin
        .from("graph_facts")
        .select("facts")
        .eq("user_id", userId)
        .eq("collector", collector)
        .maybeSingle();
      if (error) throw new Error(`Existing facts could not be read: ${error.message}`);
      const previous = (data?.facts as Record<string, unknown>) ?? {};
      metadata = previousMetadata(previous);
      next = { ...previous, ...facts };
    }

    for (const key of Object.keys(facts)) {
      metadata.fields[key] = {
        recordedAt,
        completeness: options.completeness ?? "unknown",
        ...(options.reason ? { reason: options.reason } : {}),
      };
    }
    next._evidence = metadata;

    const { error } = await admin
      .from("graph_facts")
      .upsert(
        { user_id: userId, collector, facts: next, updated_at: recordedAt },
        { onConflict: "user_id,collector" }
      );
    if (error) throw new Error(`Facts could not be saved: ${error.message}`);
  } catch (err) {
    console.error(
      `[graph] failed to save ${collector} facts for ${userId}:`,
      err instanceof Error ? err.message : err
    );
  }
}

/**
 * Assemble the reasoner's input from whatever collectors have reported.
 *
 * Account reads keep separately admitted DB snapshots but never legacy DB
 * fields or aggregate routes. An explicit repository scope may project exactly
 * one control-capable database transport only after customer-confirmed binding.
 * Neither mode guesses a join or merges two possibly different databases.
 */
export async function loadGraphInput(userId: string, repositoryId?: string): Promise<GraphInput> {
  // Source is admitted only for an explicit selected repository. Traffic joins
  // only through a repository-bound traffic site; runtime still has no binding.
  if (repositoryId !== undefined) {
    const source = await loadRepositoryGraphSource(userId, repositoryId);
    if (source.sourceCoverage === "unknown") return source;
    const databaseEvidence = await loadRepositoryDatabaseEvidence(userId, repositoryId);
    // Only traffic bound to this repository through a traffic site (2F-2b);
    // account-wide, unbound traffic never corroborates a repository.
    const trafficHotPaths = await collectTrafficFacts(userId, repositoryId);
    return {
      ...source,
      databaseEvidence,
      ...projectRepositoryDatabaseEvidence(databaseEvidence),
      ...(trafficHotPaths.length > 0 ? { trafficHotPaths } : {}),
    };
  }
  const { data, error } = await getSupabaseAdmin()
    .from("graph_facts")
    .select("collector, facts")
    .eq("user_id", userId);

  if (error) throw new Error(`Graph facts could not be read: ${error.message}`);

  const input: GraphInput = {};
  // A duplicate DB row is ambiguous even if one snapshot appears valid. The
  // storage uniqueness constraint normally prevents this; never choose one.
  const dbRows = (data ?? []).filter((row) => row.collector === "db");
  if (dbRows.length > 0) input.databaseEvidence = dbRows.length === 1
    ? await loadCurrentDatabaseEvidence(userId, dbRows[0].facts)
    : { admission: "unknown", snapshots: {} };
  for (const row of (data ?? []) as { collector: Collector; facts: Record<string, unknown> }[]) {
    if (row.collector === "source") {
      // Legacy aggregate routes carry no selected-repository identity. Keeping
      // them would correlate unrelated source and database observations.
      continue;
    } else if (row.collector === "db") {
      // Legacy shallow merges mix independent databases/transports. Matching a
      // connection still does not authorize flattening or a repository join.
      continue;
    } else if (row.collector === "traffic") {
      input.trafficHotPaths = (row.facts as unknown as TrafficFacts).hotPaths ?? [];
    } else if (row.collector === "runtime") {
      const f = row.facts as unknown as RuntimeFacts;
      // Same `!== undefined` discipline as policies above, for the same reason:
      // an absent key means no runtime collector has ever run, an empty array
      // means one ran and found nothing. Defaulting would erase the difference.
      if (f.providersRead !== undefined) input.runtimeProvidersRead = f.providersRead;
      if (f.envVars !== undefined) input.runtimeEnvVars = f.envVars;
    }
  }
  return input;
}

/** Retirement needs readable source and database evidence, not merely an
 * absence of matching paths. This deliberately retains stale findings when
 * a collector or route is unreadable. It does not establish snapshot freshness. */
export function canRetireGraphFindings(input: GraphInput): boolean {
  if (input.correlationScope === "source-only") return false;
  if (input.sourceCoverage === "partial" || input.sourceCoverage === "unknown") return false;
  return Array.isArray(input.routes) && Array.isArray(input.scanTables) &&
    Array.isArray(input.policies) && input.routes.every((route) =>
      route.identityReadable === true && route.ownershipReadable === true &&
      route.dataReadable === true && route.machineGateReadable === true &&
      route.serviceRoleReadable === true);
}

/**
 * Run the reasoner and persist its paths as findings.
 *
 * Account-wide source/provider joins are paused until verified bindings exist.
 * Existing findings remain open: missing admitted source cannot establish that
 * a path was fixed. Persistence of already-admitted inputs has a separate seam.
 */
export async function runGraphReasoner(
  userId: string
): Promise<{ total: number; newCount: number; resolvedCount: number; retainedCount?: number }> {
  const { data, error } = await getSupabaseAdmin().from("repositories").select("id")
    .eq("user_id", userId).eq("selected", true);
  if (error) throw new Error("Selected repositories could not be read");
  const repositoryIds = [...new Set((data ?? []).map((row) => row.id).filter((id): id is string => typeof id === "string" && id.length > 0))];

  // Preserve the legacy unscoped read only for accounts with no selected
  // repositories. Once repository identity exists, every new graph finding is
  // isolated to that repository; historical unscoped rows remain visible but
  // cannot suppress, resolve or be mistaken for a scoped finding.
  if (repositoryIds.length === 0) return persistGraphPaths(userId, await loadGraphInput(userId));

  const totals = { total: 0, newCount: 0, resolvedCount: 0, retainedCount: 0 };
  for (const repositoryId of repositoryIds) {
    const result = await persistGraphPaths(userId, await loadGraphInput(userId, repositoryId));
    totals.total += result.total;
    totals.newCount += result.newCount;
    totals.resolvedCount += result.resolvedCount;
    totals.retainedCount += result.retainedCount ?? 0;
  }
  return { total: totals.total, newCount: totals.newCount, resolvedCount: totals.resolvedCount,
    ...(totals.retainedCount > 0 ? { retainedCount: totals.retainedCount } : {}) };
}

/** Persistence seam for already-admitted inputs; not an evidence loader. */
export async function persistGraphPaths(
  userId: string, input: GraphInput
): Promise<{ total: number; newCount: number; resolvedCount: number; retainedCount?: number }> {

  // A path needs a route AND a database fact. With neither, there is nothing to
  // correlate and we must not archive existing paths on the strength of an empty
  // read — that would report every open path as fixed.
  // An explicitly unknown/unbound DB envelope still warrants reading existing
  // findings so the caller can report their retention, never their resolution.
  if (input.routes === undefined && input.scanTables === undefined && input.policies === undefined && input.databaseEvidence === undefined) {
    return { total: 0, newCount: 0, resolvedCount: 0 };
  }

  const paths = findAttackPaths(input);
  const admin = getSupabaseAdmin();

  let existingQuery = admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "graph");
  existingQuery = input.repositoryId
    ? existingQuery.eq("repository_id", input.repositoryId)
    : existingQuery.is("repository_id", null);
  const { data: existing, error: existingError } = await existingQuery.is("archived_at", null);

  if (existingError) throw new Error(`Graph findings could not be read: ${existingError.message}`);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(paths.map((p) => p.id));

  const absent = [...active].filter((id) => !current.has(id));
  const resolved = canRetireGraphFindings(input) ? absent : [];
  const retainedCount = absent.length - resolved.length;
  const fresh = paths.filter((p) => !active.has(p.id));
  if (fresh.length > 0) {
    // The ONE LLM call in the monitoring path, and it is gated to fire only on
    // genuinely new correlated findings — never on a routine pass, which keeps
    // routine scheduled polls at zero model calls. Batched
    // into a single call for the whole set: prompt caching does not help across
    // 48h passes, so batching is the lever that does.
    //
    // Fails into silence: on any error every path keeps the deterministic
    // wording findAttackPaths already produced, so a customer never sees a blank
    // finding because the model was unavailable.
    const narratives = await generateNarratives(fresh);

    const { error: insertError } = await admin.from("deep_findings").insert(
      fresh.map((p) => ({
        user_id: userId,
        repository_id: input.repositoryId ?? null,
        source: "graph",
        finding_id: p.id,
        severity: p.severity,
        title: p.title,
        // The guard-approved narrative when there is one, the deterministic
        // template otherwise. Never blank, and never model output that failed
        // the guard.
        consequence: narratives.accepted.get(p.id) ?? p.consequence,
        // Which collectors agreed. This is the one field that distinguishes a
        // correlated finding from a scanner's guess, and it used to be computed
        // and then discarded here — findAttackPaths already enforces
        // surfaces.length >= 2, so persisting it costs nothing and is what lets
        // the dashboard say "confirmed by two layers" instead of asserting it.
        correlation: { surfaces: p.surfaces, proven: false },
      }))
    );
    if (insertError) throw new Error(`Graph findings could not be saved: ${insertError.message}`);
  }

  // Keep previous findings visible until replacements are durably saved.
  if (resolved.length > 0) {
    let archiveQuery = admin
      .from("deep_findings")
      .update({ archived_at: new Date().toISOString() })
      .eq("user_id", userId)
      .eq("source", "graph");
    archiveQuery = input.repositoryId
      ? archiveQuery.eq("repository_id", input.repositoryId)
      : archiveQuery.is("repository_id", null);
    const { error: archiveError } = await archiveQuery.is("archived_at", null).in("finding_id", resolved);
    if (archiveError) throw new Error(`Graph findings could not be archived: ${archiveError.message}`);
  }

  if (retainedCount > 0) {
    console.warn(`[graph] retained ${retainedCount} findings for ${userId}: source or database evidence is incomplete`);
  }
  return {
    total: paths.length, newCount: fresh.length, resolvedCount: resolved.length,
    ...(retainedCount > 0 ? { retainedCount } : {}),
  };
}

/**
 * Admits selected-repository source snapshots for read-time prioritization.
 * No legacy aggregate fallback or guessed database association is allowed.
 * Bounded snapshots can promote observed paths, never demote unobserved ones.
 */
export async function loadReachabilityIndex(userId: string): Promise<ReachabilityIndex> {
  return loadRepositoryReachability(userId);
}
