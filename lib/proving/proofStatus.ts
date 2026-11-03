import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * The latest proof per finding, for the Risks board.
 *
 * A consumed authorization is one clicked test. Its outcome is the proof_runs
 * row the worker recorded (091); until then it is pending, and a job that died
 * without recording is shown as failed rather than pending forever.
 */
type ProofOutcome = "could_not_test" | "ran" | "reproduced" | "aborted";
export type ProofView =
  | { state: "pending" }
  | { state: "failed" }
  | { state: "done"; outcome: ProofOutcome; reason: string | null };

type AuthorizationRow = { id: string; repository_id: string; finding_id: string; created_at: string };
type RunRow = { authorization_id: string; outcome: ProofOutcome; reason: string | null };
type JobRow = { deduplication_key: string; status: string };

const STOPPED_JOB = new Set(["dead", "failed", "cancelled"]);

/** The latest proof per finding: authorization, run and job state combined. */
export function summarizeProofs(authorizations: AuthorizationRow[], runs: RunRow[], jobs: JobRow[]): Map<string, ProofView> {
  const runByAuthorization = new Map(runs.map((run) => [run.authorization_id, run]));
  const jobByKey = new Map(jobs.map((job) => [job.deduplication_key, job.status]));
  const latest = new Map<string, AuthorizationRow>();
  for (const auth of authorizations) {
    const key = `${auth.repository_id}|${auth.finding_id}`;
    const current = latest.get(key);
    if (!current || auth.created_at > current.created_at) latest.set(key, auth);
  }
  const views = new Map<string, ProofView>();
  for (const [key, auth] of latest) {
    const run = runByAuthorization.get(auth.id);
    if (run) views.set(key, { state: "done", outcome: run.outcome, reason: run.reason });
    else if (STOPPED_JOB.has(jobByKey.get(`proof:${auth.id}`) ?? "")) views.set(key, { state: "failed" });
    else views.set(key, { state: "pending" });
  }
  return views;
}

/**
 * The table a proof would test, or null. Only a finding that reaches exactly
 * one plain lowercase table qualifies: that name is the database table. A
 * Prisma model name (apiKey) maps to a table we cannot name with certainty.
 */
export function proofTable(blastRadius: string | null): string | null {
  const names = (blastRadius ?? "").split(",").map((name) => name.trim()).filter(Boolean);
  return names.length === 1 && /^[a-z_][a-z0-9_]{0,62}$/.test(names[0]) ? `public.${names[0]}` : null;
}

export type ProofOffer = { repositoryId: string; findingId: string; table: string; view: ProofView | null };

/**
 * The proof panel per finding row, computed on the server so the client board
 * never imports this module. Nothing is offered unless the account has the
 * proving opt-in on: that flag is off for every account until Felipe turns it
 * on, which is what keeps this out of production until approved.
 */
export function proofOffers(
  findings: { rowId: string; id: string; blastRadius: string | null; repositoryId: string | null }[],
  enabled: boolean, views: Map<string, ProofView>,
): Record<string, ProofOffer> {
  if (!enabled) return {};
  const offers: Record<string, ProofOffer> = {};
  for (const finding of findings) {
    const table = proofTable(finding.blastRadius);
    if (!table || !finding.repositoryId) continue;
    offers[finding.rowId] = { repositoryId: finding.repositoryId, findingId: finding.id, table,
      view: views.get(`${finding.repositoryId}|${finding.id}`) ?? null };
  }
  return offers;
}

/** Whether this account may run proofs: the proving opt-in on, monitor-only off. */
export async function provingEnabled(userId: string): Promise<boolean> {
  const { data } = await getSupabaseAdmin().from("user_profiles")
    .select("proving_ground_enabled, autonomy_kill_switch").eq("id", userId).maybeSingle();
  return data?.proving_ground_enabled === true && data?.autonomy_kill_switch !== true;
}

/** The latest proof per finding for the account, for the Risks board. */
export async function getProofViews(userId: string): Promise<Map<string, ProofView>> {
  const admin = getSupabaseAdmin();
  const { data: authorizations } = await admin.from("proof_authorizations")
    .select("id, repository_id, finding_id, created_at")
    .eq("user_id", userId).eq("status", "consumed")
    .order("created_at", { ascending: false }).limit(200);
  const rows = (authorizations ?? []) as AuthorizationRow[];
  if (rows.length === 0) return new Map();
  const ids = rows.map((row) => row.id);
  const [{ data: runs }, { data: jobs }] = await Promise.all([
    admin.from("proof_runs").select("authorization_id, outcome, reason").eq("user_id", userId).in("authorization_id", ids),
    admin.from("execution_jobs").select("deduplication_key, status").eq("user_id", userId).eq("kind", "proof")
      .in("deduplication_key", ids.map((id) => `proof:${id}`)),
  ]);
  return summarizeProofs(rows, (runs ?? []) as RunRow[], (jobs ?? []) as JobRow[]);
}
