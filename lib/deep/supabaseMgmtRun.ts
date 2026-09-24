// Runs the policy scan against a connected customer project and hands the
// findings and facts to the monitor worker's fenced commit (migration 068).
//
// This is the piece that finally lets lib/deep/policyScan.ts see real policies.
// Everything here is read-only (see supabaseMgmt.ts's guard).

import { getSupabaseAdmin } from "@/lib/supabase";
import { encrypt } from "@/lib/crypto";
import {
  getUsableToken,
  fetchPolicies,
  fetchAdvisors,
  fetchAuthConfig,
  fetchSchemaColumns,
  fetchRowCounts,
  fetchAuthAuditLog,
  fetchColumnGrants,
  fetchDatabaseCapabilities,
  fetchStorageConfig,
  fetchBackupConfig,
  fetchRealtimeAndHooks,
} from "./supabaseMgmt";
import { analyzePolicies, mapAdvisors, mergePolicyFindings } from "./policyScan";
import { scanAuthConfig } from "./authConfigScan";
import { scanAuthPolicy } from "./authPolicyScan";
import { analyzeGrants } from "./grantScan";
import { scanExtensions } from "./extensionScan";
import { scanStorage, checkBackups } from "./storageScan";
import { scanRealtimeAndHooks } from "./realtimeScan";
import { deriveAppUrl } from "./deriveAppUrl";
import type { SupabaseManagementSnapshot } from "@/lib/graph/graphRun";
import { currentConnectionEpoch } from "./providerRepositoryMap";
import { buildInventory } from "@/lib/exposure/model";
import { runAuthLogScan } from "@/lib/runtime/authRun";
import { runProvingGround } from "@/lib/proving/run";
import { provingHost } from "@/lib/proving/host";
import { findAttackPaths } from "@/lib/graph/attackPaths";
import { loadGraphInput } from "@/lib/graph/graphRun";
import { buildAuthzFacts } from "@/lib/graph/graph";
import { CollectorShapeError } from "./apiSchemas";
import type { GithubFinding } from "./githubScan";
import type { Finding } from "@/lib/monitoring/findings";
import type { ProviderCommit } from "@/lib/monitoring/registry";

export interface PolicyScanOutcome {
  ok: boolean;
  findings: number;
  newFindings?: GithubFinding[];
  reason?: string;
}

// The fetched object is intentionally loose and may contain SMTP/OAuth secrets.
// Existing checks use it only in memory; graph storage needs two boolean flags.
function graphAuthConfig(config: Awaited<ReturnType<typeof fetchAuthConfig>>): SupabaseManagementSnapshot["authConfig"] {
  if (config === null) return null;
  return {
    ...(typeof config.disable_signup === "boolean" ? { disable_signup: config.disable_signup } : {}),
    ...(typeof config.mailer_autoconfirm === "boolean" ? { mailer_autoconfirm: config.mailer_autoconfirm } : {}),
  };
}

const ABORTED: PolicyScanOutcome = { ok: false, findings: 0, reason: "aborted" };

export async function runPolicyScan(
  userId: string,
  { signal, commit }: { signal?: AbortSignal; commit: ProviderCommit },
): Promise<PolicyScanOutcome> {
  const admin = getSupabaseAdmin();

  const { data: row, error: profileError } = await admin
    .from("user_profiles")
    .select(
      "supabase_mgmt_token_encrypted, supabase_mgmt_connection_epoch, supabase_mgmt_refresh_encrypted, supabase_mgmt_expires_at, supabase_mgmt_project_ref, monitored_app_url"
    )
    .eq("id", userId)
    .maybeSingle();

  if (profileError || typeof row?.supabase_mgmt_token_encrypted !== "string" ||
      !row.supabase_mgmt_token_encrypted.trim() || typeof row.supabase_mgmt_project_ref !== "string" ||
      !row.supabase_mgmt_project_ref.trim()) {
    return { ok: false, findings: 0, reason: "not_connected" };
  }
  // Read with the credential; an OAuth refresh below keeps this identity.
  const connectionFingerprint = currentConnectionEpoch(row.supabase_mgmt_token_encrypted, row.supabase_mgmt_connection_epoch);
  if (!connectionFingerprint) return { ok: false, findings: 0, reason: "not_connected" };

  const projectRef = row.supabase_mgmt_project_ref;
  const connectionCiphertext = row.supabase_mgmt_token_encrypted;
  let token;
  try {
    const usable = await getUsableToken(row);
    if (!usable) return { ok: false, findings: 0, reason: "not_connected" };
    token = usable.token;

    // Persist a refreshed token so the next pass doesn't have to refresh again.
    if (usable.refreshed) {
      const refreshedCiphertext = encrypt(token.accessToken);
      const { data: persisted, error: refreshError } = await admin
        .from("user_profiles")
        .update({
          supabase_mgmt_token_encrypted: refreshedCiphertext,
          supabase_mgmt_refresh_encrypted: token.refreshToken
            ? encrypt(token.refreshToken)
            : row.supabase_mgmt_refresh_encrypted,
          supabase_mgmt_expires_at: token.expiresAt,
        })
        .eq("id", userId)
        .eq("supabase_mgmt_project_ref", projectRef)
        .eq("supabase_mgmt_token_encrypted", connectionCiphertext)
        .select("supabase_mgmt_token_encrypted")
        .maybeSingle();
      // A disconnect/reconnect or failed write must not publish a fingerprint
      // for a credential we only intended to store. This guards refresh only;
      // in-flight collection still needs current-connection admission later.
      if (refreshError || persisted?.supabase_mgmt_token_encrypted !== refreshedCiphertext) {
        return { ok: false, findings: 0, reason: "auth_failed" };
      }
    }
  } catch {
    // A revoked or expired connection is a normal state, not an error worth
    // alarming the customer about — the panel shows "reconnect".
    return { ok: false, findings: 0, reason: "auth_failed" };
  }

  // The OAuth refresh above deliberately ignores cancellation: the provider may
  // already have rotated the refresh token, and dropping the replacement would
  // strand the connection. From here on, a cancelled pass reads and writes nothing.
  if (signal?.aborted) return ABORTED;

  let findings;
  let committed: Finding[];
  try {
    // POLICIES ARE LOAD-BEARING; ADVISORS CORROBORATE. The two get different
    // treatment on a shape failure, deliberately.
    //
    // If the policy fetch stops returning policy-shaped rows we must abort the
    // whole scan: `analyzePolicies([])` finds nothing, and persisting that would
    // ARCHIVE every real policy finding the customer already has as "resolved".
    // A parser breaking would look exactly like the customer fixing everything.
    //
    // Advisors are an independent second witness to facts the policies already
    // establish, and the payload genuinely varies by Supabase version, so a
    // shape change there degrades to "no advisor corroboration" rather than
    // costing the customer their scan. The graph still records that policies
    // were read, so nothing is silently reported as protected.
    const [policies, authConfig] = await Promise.all([
      fetchPolicies(token.accessToken, projectRef, signal),
      fetchAuthConfig(token.accessToken, projectRef, signal),
    ]);

    let advisors: Awaited<ReturnType<typeof fetchAdvisors>> = [];
    let advisorsOk = true;
    try {
      advisors = await fetchAdvisors(token.accessToken, projectRef, signal);
    } catch (err) {
      advisorsOk = false;
      console.error(
        `[supabaseMgmt] advisor shape changed for ${userId}, continuing without corroboration:`,
        err instanceof Error ? err.message : err
      );
    }
    findings = [
      ...mergePolicyFindings(analyzePolicies(policies), mapAdvisors(advisors)),
      // B7 + Site URL. fetchAuthConfig returns null when the request fails, and
      // scanAuthConfig treats null as "we learned nothing" rather than as a
      // clean bill of health — a failed fetch must never look like a pass.
      ...scanAuthConfig(authConfig),
      // B1/B2/B4/B5/B11 — same config object, no extra request.
      ...scanAuthPolicy(authConfig),
      // A5 — column grants to anon/authenticated. The bug we shipped ourselves.
      ...analyzeGrants(await fetchColumnGrants(token.accessToken, projectRef, signal)),
      // A8/A15/A16/A17 — what the database itself can reach.
      ...scanExtensions(await fetchDatabaseCapabilities(token.accessToken, projectRef, signal)),
      // A12/A13 storage, A19 recovery posture.
      ...scanStorage(await fetchStorageConfig(token.accessToken, projectRef, signal)),
      ...checkBackups(await fetchBackupConfig(token.accessToken, projectRef, signal)),
      // A14 Realtime authorisation, A20 auth-hook claim integrity.
      ...scanRealtimeAndHooks(await fetchRealtimeAndHooks(token.accessToken, projectRef, signal)),
    ];

    // Capture one self-contained project/credential observation. Do not fill
    // failed reads from legacy merged facts or another database transport.
    const storedAuthConfig = graphAuthConfig(authConfig);
    const supabaseManagementSnapshot: SupabaseManagementSnapshot = {
      collector: "supabase-management", authzProvider: "postgres-rls",
      projectRef, connectionFingerprint, recordedAt: new Date().toISOString(),
      completeness: "unknown", policies, authConfig: storedAuthConfig,
      ...(advisorsOk ? { advisors } : {}),
    };
    signal?.throwIfAborted();
    // Keep legacy flat observations for compatibility, but never persist the
    // loose auth config. Failed advisors remain omitted in the snapshot even
    // though the existing merge may retain an older flat advisor set.
    const dbFacts: Record<string, unknown> = {
      policies, authConfig: storedAuthConfig, ...(advisorsOk ? { advisors } : {}), supabaseManagementSnapshot,
    };

    // A21 exposure inventory. SCHEMA ONLY — column names and row counts, never
    // a value. Best-effort: a project we cannot enumerate simply has no
    // inventory, which the model reports as "we don't know" rather than zero.
    try {
      const columns = await fetchSchemaColumns(token.accessToken, projectRef, signal);
      const tables = [...new Set(columns.map((c) => c.table))];
      const rowCounts = await fetchRowCounts(token.accessToken, projectRef, tables, signal);
      signal?.throwIfAborted();
      dbFacts.inventory = buildInventory(columns, rowCounts);
    } catch (err) {
      console.error(
        "[supabaseMgmt] schema inventory failed:",
        err instanceof Error ? err.message : err
      );
    }

    // Snapshot, inventory, and findings commit together under the monitor
    // job's lease and this connection epoch, or not at all (3F-C2c). The side
    // effects below run only after a successful commit.
    signal?.throwIfAborted();
    try {
      committed = await commit({
        transport: "supabase-management", identity: connectionFingerprint,
        facts: dbFacts, findings, retire: true,
      });
    } catch {
      console.error(`[supabaseMgmt] result not committed for ${userId}`);
      return { ok: false, findings: 0, reason: "not_committed" };
    }

    signal?.throwIfAborted();
    // The proving ground. Inert unless the customer opted in AND the kill switch
    // is off — both default off in migration 040, so this changes nothing for
    // anyone until they ask for it. Wired here because this is the only place
    // holding a Management API token and the project ref together.
    //
    // What it probes comes from the reasoner: the graph decides WHAT to test,
    // the proving ground decides whether it is TRUE.
    try {
      const { data: settingsRow } = await admin
        .from("user_profiles")
        .select("proving_ground_enabled, autonomy_kill_switch")
        .eq("id", userId)
        .maybeSingle();

      const settings = {
        provingGroundEnabled: settingsRow?.proving_ground_enabled === true,
        killSwitchOn: settingsRow?.autonomy_kill_switch === true,
      };

      if (settings.provingGroundEnabled && !settings.killSwitchOn) {
        // Uses the FULL graph input, not just the facts collected in this pass.
        // Attack paths need a route -> table edge, and routes come from the
        // source collector on a different trigger — so building paths from
        // policies and advisors alone yields zero targets and the proving ground
        // would silently never probe anything.
        const graphInput = await loadGraphInput(userId);
        const suspected = new Set(
          findAttackPaths({ ...graphInput, policies, advisors })
            .filter((p) => p.id.includes("tenant_isolation") || p.id.includes("anon_read"))
            .map((p) => p.id.split(":").pop() ?? "")
            .filter(Boolean)
        );

        // Fallback that makes this useful without GitHub connected: a policy
        // that filters nothing is worth PROVING whether or not we can see a
        // route reaching it, because anything holding the anon key can use it
        // directly. Without this the proving ground would be dead for every
        // customer who connected only Supabase.
        for (const t of buildAuthzFacts({ policies, advisors }).values()) {
          if (t.unconditionalGrant || t.enforced === false) suspected.add(t.qualified);
        }

        const schema = new Map<string, string[]>();
        for (const c of await fetchSchemaColumns(token.accessToken, projectRef, signal)) {
          schema.set(c.table, [...(schema.get(c.table) ?? []), c.column]);
        }

        // Policies grouped per table, so the replica path can rebuild one.
        const policiesByTable = new Map<string, typeof policies>();
        for (const policy of policies) {
          const list = policiesByTable.get(policy.tablename) ?? [];
          list.push(policy);
          policiesByTable.set(policy.tablename, list);
        }

        signal?.throwIfAborted();
        const result = await runProvingGround({
          userId,
          customerToken: token.accessToken,
          customerRef: projectRef,
          settings,
          suspectedTables: [...suspected],
          schema,
          policiesByTable,
          host: provingHost(),
        });
        if (result.ran) {
          await admin
            .from("user_profiles")
            .update({ last_proving_run_at: new Date().toISOString() })
            .eq("id", userId);
        }
      }
    } catch (err) {
      console.error(
        "[supabaseMgmt] proving ground failed:",
        err instanceof Error ? err.message : err
      );
    }

    // E5-E7 runtime detection from the auth audit log. Zero friction: this
    // needs no snippet installed, only the Supabase connection they already
    // made. Best-effort — the log endpoint is experimental.
    signal?.throwIfAborted();
    try {
      const events = await fetchAuthAuditLog(token.accessToken, projectRef, signal);
      signal?.throwIfAborted();
      await runAuthLogScan(userId, events);
    } catch (err) {
      console.error("[supabaseMgmt] auth log scan failed:", err instanceof Error ? err.message : err);
    }

    // 2F-4: no-install traffic from the Supabase API gateway log, judged per
    // source and stored only for repositories confirmed for this project.
    // Best-effort; an unreadable log leaves prior observations as they were.
    signal?.throwIfAborted();
    try {
      const { collectSupabaseEdgeTraffic } = await import("@/lib/traffic/edgeCollect");
      const edge = await collectSupabaseEdgeTraffic(userId, token.accessToken, projectRef, signal);
      if (edge.status === "unread") console.error("[supabaseMgmt] gateway log unread; traffic observations unchanged");
    } catch (err) {
      console.error("[supabaseMgmt] gateway traffic collection failed:", err instanceof Error ? err.message : err);
    }

    // Unit 5: work out the app URL instead of asking for it.
    //
    // The onboarding field for this was optional, so people skipped it, and
    // skipping it silently disabled a whole surface — exposed paths, source
    // maps, secrets in the shipped bundle, email authentication. That produced
    // the worst possible state: a customer who believes they are fully monitored
    // while a third of the product isn't running.
    //
    // Supabase already knows the answer, because it needs the same URL to send
    // password-reset email. Only fills a BLANK value: a URL the customer typed
    // themselves is deliberate and always wins.
    signal?.throwIfAborted();
    if (!row.monitored_app_url) {
      const derived = deriveAppUrl(authConfig);
      if (derived) {
        await admin
          .from("user_profiles")
          .update({ monitored_app_url: derived })
          .eq("id", userId)
          .then(
            () => {},
            () => {}
          );
        console.log(`[supabaseMgmt] derived app URL for ${userId}: ${derived}`);
      }
    }
  } catch (err) {
    if (signal?.aborted) return ABORTED;
    // A shape mismatch is reported distinctly from a generic failure, because it
    // means something different and needs a different response: a transient
    // network error resolves itself, an API contract change needs us to ship a
    // schema update. It is OUR bug, not the customer's, and it should be
    // findable in a log search rather than buried in "scan_failed".
    //
    // Either way the important property is the same — we return before the
    // persistence block below, so nothing is written and nothing is archived. A
    // broken parser cannot mark a customer's real findings resolved.
    if (err instanceof CollectorShapeError) {
      console.error(
        `[supabaseMgmt] SHAPE MISMATCH for ${userId} — the scan was abandoned rather than ` +
          `reported clean. ${err.message}`
      );
      return { ok: false, findings: 0, reason: "shape_mismatch" };
    }
    console.error(
      "[supabaseMgmt] policy scan failed:",
      err instanceof Error ? err.message : err
    );
    return { ok: false, findings: 0, reason: "scan_failed" };
  }

  return { ok: true, findings: findings.length, newFindings: committed as GithubFinding[] };
}
