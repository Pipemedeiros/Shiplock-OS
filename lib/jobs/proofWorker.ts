import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";
import { loadRepositoryDatabaseEvidence } from "@/lib/graph/repositoryDatabase";
import { openEmbeddedHost } from "@/lib/proving/embeddedHost";
import { openArena, type Arena, type ProvingHost } from "@/lib/proving/arena";
import { buildControlProbeSql, buildLeakProbeSql } from "@/lib/proving/replica";
import { pickOwnerColumn } from "@/lib/proving/tenantProbe";
import type { PgPolicy } from "@/lib/proving/policyTypes";
import { claimJob, executeClaimedJob, PermanentJobError, withLeaseHeartbeat, type ClaimedJob } from "./queue";

/**
 * One customer click, one proof (migrations 090, 091).
 *
 * The job carries a consumed per-test authorization: one finding, one table,
 * one selected repository. The worker rebuilds that table and the policies
 * from the current, repository-bound database snapshot inside a fresh embedded
 * Postgres (openEmbeddedHost: in process, no network, synthetic tenants only,
 * discarded afterwards) and records exactly one outcome under the live lease:
 *
 *   could_not_test  a precondition failed; nothing was concluded
 *   ran             the probes ran and tenant A could not read tenant B's row
 *   reproduced      tenant A read tenant B's row on the disposable copy
 *   aborted         the statement budget or a time/resource limit stopped it
 *
 * "ran" is never "secure": it is one probe on a reconstruction. This worker
 * never touches a customer database, never uses the hosted proving project
 * (provingHost), and never writes findings: the proof record is its only write.
 */

type Outcome = { outcome: "could_not_test" | "ran" | "reproduced" | "aborted"; reason: string | null };
const couldNot = (reason: string): Outcome => ({ outcome: "could_not_test", reason });

const authorizationSchema = z.object({
  id: z.uuid(), user_id: z.uuid(), repository_id: z.uuid(), finding_id: z.string().min(1),
  table_name: z.string().regex(/^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$/),
  target_kind: z.literal("replica"), status: z.literal("consumed"), statement_budget: z.number().int().min(1).max(200),
});

class StatementBudgetExceeded extends Error {}

/** Statements in one SQL text. Over-counting is the safe direction for a budget. */
const statementCount = (sql: string) => sql.split(";").filter((part) => part.trim().length > 0).length;
const isTeardown = (sql: string) => /^drop schema if exists "proving_[a-z0-9]+" cascade;$/.test(sql.trim());

/** How a stopped replica is reported: the parent kills the thread on a
 * timeout, and a resource limit terminates it; both end the run as aborted. */
function stopReason(err: unknown): string | null {
  const message = err instanceof Error ? err.message : "";
  if (err instanceof StatementBudgetExceeded) return "statement_budget";
  if (/memory|resource|temp_file_limit/i.test(message)) return "resource_limit";
  if (/timeout|exceeded \d+ ms|stopped/i.test(message)) return "time_limit";
  return null;
}

const num = (rows: Record<string, unknown>[], key: string): number => {
  const value = rows[0]?.[key];
  return typeof value === "number" ? value : Number.parseInt(String(value ?? 0), 10) || 0;
};

/** The finding's blast radius must name the authorized table. */
function findingNamesTable(blastRadius: unknown, schema: string, table: string): boolean {
  if (typeof blastRadius !== "string") return false;
  const names = blastRadius.match(/[A-Za-z_][\w.]*/g) ?? [];
  return names.some((name) => name === table || name === `${schema}.${table}`);
}

/** Runs one authorized proof on the embedded replica and records its outcome. */
export async function executeProofJob(job: ClaimedJob): Promise<void> {
  const key = /^proof:([0-9a-f-]{36})$/.exec(job.deduplication_key ?? "");
  if (job.kind !== "proof" || !job.repository_id || job.audit_run_id || !key) {
    throw new PermanentJobError("Invalid proof context");
  }
  const admin = getSupabaseAdmin();
  const userId = job.user_id;
  const repositoryId = job.repository_id;

  // Recorded work is never rerun: one authorization, one outcome.
  const { data: existing, error: existingError } = await admin.from("proof_runs").select("id").eq("job_id", job.id).maybeSingle();
  if (existingError) throw new Error("Proof record could not be read");
  if (existing) return;

  const { data: rawAuthorization, error: authorizationError } = await admin.from("proof_authorizations")
    .select("id, user_id, repository_id, finding_id, table_name, target_kind, status, statement_budget")
    .eq("id", key[1]).eq("user_id", userId).maybeSingle();
  if (authorizationError) throw new Error("Proof authorization could not be read");
  const parsed = authorizationSchema.safeParse(rawAuthorization);
  if (!parsed.success || parsed.data.repository_id !== repositoryId) throw new PermanentJobError("Proof authorization changed");
  const authorization = parsed.data;
  const [schema, table] = authorization.table_name.split(".");

  let statements = 0;
  const record = async ({ outcome, reason }: Outcome) => {
    const { error } = await admin.rpc("record_proof_run", {
      p_user: userId, p_job: job.id, p_token: job.lease_token, p_outcome: outcome, p_reason: reason,
      p_statements: Math.min(statements, authorization.statement_budget),
    });
    if (error) throw new Error("Proof outcome could not be recorded");
  };

  await withLeaseHeartbeat(job, async () => record(await prove()));

  async function prove(): Promise<Outcome> {
    // A failed read retries the job; only a read answer becomes an outcome.
    const { data: profile, error: profileError } = await admin.from("user_profiles")
      .select("proving_ground_enabled, autonomy_kill_switch").eq("id", userId).maybeSingle();
    if (profileError) throw new Error("Proof settings could not be read");
    if (profile?.autonomy_kill_switch === true) return couldNot("kill_switch");
    if (profile?.proving_ground_enabled !== true) return couldNot("not_enabled");

    const { data: repository, error: repositoryError } = await admin.from("repositories").select("selected")
      .eq("id", repositoryId).eq("user_id", userId).maybeSingle();
    if (repositoryError) throw new Error("Proof repository could not be read");
    if (repository?.selected !== true) return couldNot("repository_unselected");

    const { data: finding, error: findingError } = await admin.from("deep_findings").select("finding_id, blast_radius, archived_at")
      .eq("user_id", userId).eq("repository_id", repositoryId).eq("finding_id", authorization.finding_id)
      .is("archived_at", null).maybeSingle();
    if (findingError) throw new Error("Proof finding could not be read");
    if (!finding || finding.archived_at !== null || !findingNamesTable(finding.blast_radius, schema, table)) {
      return couldNot("finding_mismatch");
    }
    // The stored columns come from the public schema only.
    if (schema !== "public") return couldNot("unsupported_schema");

    // Policies and columns only from the current, repository-bound snapshot.
    const evidence = await loadRepositoryDatabaseEvidence(userId, repositoryId);
    const snapshot = (evidence.snapshots.directPostgresSnapshot ?? evidence.snapshots.supabaseManagementSnapshot) as
      { policies?: PgPolicy[]; columns?: { table: string; column: string }[] } | undefined;
    if (evidence.admission !== "connection-matched" || !snapshot?.policies) return couldNot("database_unread");
    if (!snapshot.columns) return couldNot("columns_unread");
    // Never an invented owner column: only one the snapshot observed.
    const ownerColumn = pickOwnerColumn(snapshot.columns.filter((c) => c.table === table).map((c) => c.column));
    if (!ownerColumn) return couldNot("no_owner_column");
    const policies = snapshot.policies.filter((p) => p.schemaname === schema && p.tablename === table);

    let embedded: Awaited<ReturnType<typeof openEmbeddedHost>>;
    try {
      embedded = await openEmbeddedHost();
    } catch {
      // Local and deterministic: a missing worker file or no memory will not
      // fix itself on retry, and the customer's test must not wait forever.
      return couldNot("replica_unavailable");
    }
    let stopped: string | null = null;
    // Every statement counts against the authorization's budget, except the
    // teardown, which is always allowed so a stopped run still cleans up.
    const host: ProvingHost = {
      token: embedded.token, projectRef: embedded.projectRef,
      run: async (ref, sql) => {
        if (!isTeardown(sql)) {
          const count = statementCount(sql);
          if (statements + count > authorization.statement_budget) {
            stopped = "statement_budget";
            throw new StatementBudgetExceeded("Proof statement budget reached.");
          }
          statements += count;
        }
        try {
          return await embedded.run(ref, sql);
        } catch (err) {
          stopped ??= stopReason(err);
          throw err;
        }
      },
    };
    let arena: Arena | null = null;
    try {
      const opened = await openArena({
        customerToken: "", customerRef: `repository:${repositoryId}`,
        settings: { killSwitchOn: false, provingGroundEnabled: true },
        table, ownerColumn, policies,
      }, host);
      if (stopped) return { outcome: "aborted", reason: stopped };
      if (!opened.arena) return couldNot(policies.length === 0 ? "no_policies" : "not_replicable");
      arena = opened.arena;
      return await probe(arena, ownerColumn);
    } catch (err) {
      const reason = stopped ?? stopReason(err);
      if (reason) return { outcome: "aborted", reason };
      return couldNot("replica_error");
    } finally {
      if (arena) await arena.teardown();
      await embedded.close();
    }
  }

  async function probe(arena: Arena, ownerColumn: string): Promise<Outcome> {
    // The control gates everything: tenant A must see exactly its own row, or
    // the reconstruction is broken and "no leak" would mean nothing.
    const control = num(await arena.run(buildControlProbeSql(arena.schema, table, ownerColumn)), "visible");
    if (control !== 1) return couldNot("control_failed");
    const leaked = num(await arena.run(buildLeakProbeSql(arena.schema, table, ownerColumn)), "leaked");
    if (leaked > 0) return { outcome: "reproduced", reason: null };
    // Variants the fixed probe cannot express need a model, and ShipLock makes
    // no model call: the test ran and reproduced nothing, which is not clean.
    return { outcome: "ran", reason: null };
  }
}

/** Claims and runs one proof job; false when the queue had none. */
export async function runNextProofJob(): Promise<boolean> {
  const job = await claimJob("proof");
  if (!job) return false;
  await executeClaimedJob(job, [executeProofJob]);
  return true;
}
