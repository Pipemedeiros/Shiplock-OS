import { getSupabaseAdmin } from "@/lib/supabase";
import { decrypt } from "@/lib/crypto";
import { currentConnectionEpoch, newConnectionEpoch } from "./providerRepositoryMap";
import { analyzePolicies } from "./policyScan";
import { analyzeGrants } from "./grantScan";
import {
  collectDirectFacts,
  parseConnectionString,
  PostgresConnectionError,
} from "./postgresDirect";
import { CollectorShapeError } from "./apiSchemas";
import type { Finding } from "@/lib/monitoring/findings";
import type { ProviderCommit } from "@/lib/monitoring/registry";
import type { GithubFinding } from "./githubScan";

// Running the direct-Postgres collector and committing what it found.
//
// Mirrors lib/deep/supabaseMgmtRun.ts deliberately: same `deep_findings` source
// (`policy`), same archive-on-resolve contract, same `db` graph facts, all
// through the monitor worker's fenced commit (migration 068). Downstream — the reasoner, the fix lanes, the agent brief, MCP, the
// dashboard — cannot tell which transport produced the facts, and should not be
// able to. That is the whole point of the provider seam in lib/graph/graph.ts.
//
// THE THING THAT MAKES THIS ACTUALLY WORK: it is registered as a monitoring
// collector (lib/monitoring/collectors.ts) rather than being reachable only from
// a settings button. This repository has had collectors that existed but were
// never called; the fix each time was scheduling, not more collector code.
// Do not remove it from the registry and leave the route.

export interface DirectScanOutcome {
  ok: boolean;
  findings: number;
  newFindings?: GithubFinding[];
  reason?:
    | "not_connected"
    | "auth_failed"
    | "blocked_host"
    | "not_read_only"
    | "shape_mismatch"
    | "scan_failed"
    | "aborted"
    | "not_committed";
}

interface ProfileRow {
  postgres_dsn_encrypted: string | null;
  postgres_connection_epoch: string | null;
}

/**
 * Read and decrypt the stored connection string.
 *
 * Returns null rather than throwing when absent, because "this customer is on
 * Supabase instead" is the common case, not an error.
 */
async function loadConnection(userId: string): Promise<{ raw: string; fingerprint: string } | null> {
  const { data, error } = await getSupabaseAdmin()
    .from("user_profiles")
    .select("postgres_dsn_encrypted, postgres_connection_epoch")
    .eq("id", userId)
    .maybeSingle<ProfileRow>();

  const fingerprint = currentConnectionEpoch(data?.postgres_dsn_encrypted, data?.postgres_connection_epoch);
  if (error || !fingerprint || typeof data?.postgres_dsn_encrypted !== "string") return null;
  try {
    const raw = decrypt(data.postgres_dsn_encrypted);
    if (!raw) return null;
    return { raw, fingerprint };
  } catch {
    // A key rotation that left an undecryptable value must not look like a clean
    // scan. Treat it as not connected so the customer is prompted to reconnect.
    console.error(`[postgresDirect] could not decrypt stored DSN for ${userId}`);
    return null;
  }
}

/**
 * Scan a customer's own Postgres and feed the graph.
 *
 * Note what is deliberately NOT produced here: `advisors` and `authConfig`.
 * Those are Supabase platform features with no SQL equivalent. Writing empty
 * arrays for them would be a lie in the most damaging direction — the graph
 * treats an absent fact as "unknown" and an empty one as "checked, nothing
 * there", and the second would silently downgrade real findings to clean.
 * The fenced commit merges these keys into existing facts for the same reason.
 */
const ABORTED: DirectScanOutcome = { ok: false, findings: 0, reason: "aborted" };

export async function runDirectPostgresScan(
  userId: string,
  { signal, commit }: { signal?: AbortSignal; commit: ProviderCommit },
): Promise<DirectScanOutcome> {
  const admin = getSupabaseAdmin();

  const loaded = await loadConnection(userId);
  if (!loaded) return { ok: false, findings: 0, reason: "not_connected" };

  let findings: GithubFinding[];
  let committed: Finding[];
  try {
    const connection = parseConnectionString(loaded.raw);
    const facts = await collectDirectFacts(connection, undefined, signal);
    const failed = facts.grants === null ? ["grants:"] : [];

    findings = [
      ...analyzePolicies(facts.policies),
      // A5 — column grants to publicly reachable roles. Returns nothing on a
      // database without Supabase's role names, which is correct rather than
      // clean: no such role means no such exposure.
      ...analyzeGrants(facts.grants ?? []),
    ];

    signal?.throwIfAborted();
    // Raw facts for the reasoner, not our verdicts. `authzProvider` is stamped
    // explicitly rather than left to inference, so this stays correct if a
    // non-Postgres collector is ever added alongside it.
    const dbFacts = {
      authzProvider: "postgres-rls" as const,
      policies: facts.policies,
      scanTables: facts.scanTables,
      // Replaced as one transport-local object. It cannot borrow old advisors,
      // auth config or table observations from another database producer.
      directPostgresSnapshot: {
        collector: "postgres-direct" as const, authzProvider: "postgres-rls" as const,
        connectionFingerprint: loaded.fingerprint, recordedAt: new Date().toISOString(),
        completeness: "unknown" as const, policies: facts.policies, scanTables: facts.scanTables,
      },
    };

    // Facts and findings commit together under the monitor job's lease and
    // this connection epoch, or not at all (3F-C2c).
    try {
      committed = await commit({
        transport: "postgres-direct", identity: loaded.fingerprint, facts: dbFacts,
        findings, retire: true, unread: failed,
        // No scope: a database host is kept out of stored evidence; the
        // connection epoch already identifies the connection.
        snapshot: { scope: null, failed },
      });
    } catch {
      console.error(`[postgresDirect] result not committed for ${userId}`);
      return { ok: false, findings: 0, reason: "not_committed" };
    }

    // A display timestamp, not evidence; written after the evidence commit.
    await admin
      .from("user_profiles")
      .update({ postgres_last_scan_at: new Date().toISOString() })
      .eq("id", userId);
  } catch (err) {
    // A cancelled pass is neither a connection nor a scan failure; write nothing.
    if (signal?.aborted) return ABORTED;
    if (err instanceof PostgresConnectionError) {
      // Expected, actionable states — not incidents. The panel shows the reason.
      console.error(`[postgresDirect] ${err.code} for ${userId}`);
      return {
        ok: false,
        findings: 0,
        reason:
          err.code === "auth_failed"
            ? "auth_failed"
            : err.code === "blocked_host"
              ? "blocked_host"
              : err.code === "not_read_only"
                ? "not_read_only"
                : "scan_failed",
      };
    }
    if (err instanceof CollectorShapeError) {
      // Our bug, not theirs. Reported distinctly and, critically, returned
      // BEFORE the persistence block — a broken parser must never archive a
      // customer's real findings as resolved.
      console.error(
        `[postgresDirect] SHAPE MISMATCH for ${userId} — scan abandoned rather than ` +
          `reported clean. ${err.message}`
      );
      return { ok: false, findings: 0, reason: "shape_mismatch" };
    }
    console.error(
      "[postgresDirect] scan failed:",
      err instanceof Error ? err.message : err
    );
    return { ok: false, findings: 0, reason: "scan_failed" };
  }

  return { ok: true, findings: findings.length, newFindings: committed as GithubFinding[] };
}

/**
 * Validate and store a connection string the customer just supplied.
 *
 * Connects immediately and refuses to save anything that does not work AND is
 * not read-only. Storing first and discovering later would leave a credential we
 * cannot use, and — worse — would let a customer believe a writable role was
 * accepted on our terms.
 */
export async function connectDirectPostgres(
  userId: string,
  raw: string
): Promise<{ ok: true; display: string } | { ok: false; code: string; message: string }> {
  let connection;
  try {
    connection = parseConnectionString(raw);
    // The probe IS the validation — it opens a read-only session and asserts the
    // role cannot write before we agree to hold the credential at all.
    await collectDirectFacts(connection);
  } catch (err) {
    if (err instanceof PostgresConnectionError) {
      return { ok: false, code: err.code, message: err.message };
    }
    return {
      ok: false,
      code: "scan_failed",
      message: "We connected, but could not read your policies. Check the role's grants.",
    };
  }

  const { encrypt } = await import("@/lib/crypto");
  const display = `${connection.host}/${connection.database}`;

  await getSupabaseAdmin()
    .from("user_profiles")
    .update({
      postgres_dsn_encrypted: encrypt(connection.dsn),
      postgres_connection_epoch: newConnectionEpoch(),
      postgres_display: display,
      postgres_connected_at: new Date().toISOString(),
    })
    .eq("id", userId);

  return { ok: true, display };
}

/** Forget the credential. Findings are archived, not deleted — history stands. */
export async function disconnectDirectPostgres(userId: string): Promise<void> {
  const admin = getSupabaseAdmin();
  await admin
    .from("user_profiles")
    .update({
      postgres_dsn_encrypted: null,
      postgres_connection_epoch: null,
      postgres_display: null,
      postgres_connected_at: null,
    })
    .eq("id", userId);

  await admin
    .from("deep_findings")
    .update({ archived_at: new Date().toISOString() })
    .eq("user_id", userId)
    .eq("source", "postgres-direct")
    .is("archived_at", null);
}
