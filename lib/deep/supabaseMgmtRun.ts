// Runs the policy scan against a connected customer project and persists the
// findings, the same way lib/deep/githubRun.ts does for source findings.
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
import { saveFacts } from "@/lib/graph/graphRun";
import { buildInventory } from "@/lib/exposure/model";
import { runAuthLogScan } from "@/lib/runtime/authRun";
import { runProvingGround } from "@/lib/proving/run";
import { findAttackPaths } from "@/lib/graph/attackPaths";
import { loadGraphInput } from "@/lib/graph/graphRun";
import { buildTableFacts } from "@/lib/graph/graph";

export interface PolicyScanOutcome {
  ok: boolean;
  findings: number;
  reason?: string;
}

export async function runPolicyScan(userId: string): Promise<PolicyScanOutcome> {
  const admin = getSupabaseAdmin();

  const { data: row } = await admin
    .from("user_profiles")
    .select(
      "supabase_mgmt_token_encrypted, supabase_mgmt_refresh_encrypted, supabase_mgmt_expires_at, supabase_mgmt_project_ref, monitored_app_url"
    )
    .eq("id", userId)
    .maybeSingle();

  if (!row?.supabase_mgmt_token_encrypted || !row.supabase_mgmt_project_ref) {
    return { ok: false, findings: 0, reason: "not_connected" };
  }

  let token;
  try {
    const usable = await getUsableToken(row);
    if (!usable) return { ok: false, findings: 0, reason: "not_connected" };
    token = usable.token;

    // Persist a refreshed token so the next pass doesn't have to refresh again.
    if (usable.refreshed) {
      await admin
        .from("user_profiles")
        .update({
          supabase_mgmt_token_encrypted: encrypt(token.accessToken),
          supabase_mgmt_refresh_encrypted: token.refreshToken
            ? encrypt(token.refreshToken)
            : row.supabase_mgmt_refresh_encrypted,
          supabase_mgmt_expires_at: token.expiresAt,
        })
        .eq("id", userId);
    }
  } catch {
    // A revoked or expired connection is a normal state, not an error worth
    // alarming the customer about — the panel shows "reconnect".
    return { ok: false, findings: 0, reason: "auth_failed" };
  }

  const projectRef = row.supabase_mgmt_project_ref as string;

  let findings;
  try {
    const [policies, advisors, authConfig] = await Promise.all([
      fetchPolicies(token.accessToken, projectRef),
      fetchAdvisors(token.accessToken, projectRef),
      fetchAuthConfig(token.accessToken, projectRef),
    ]);
    findings = [
      ...mergePolicyFindings(analyzePolicies(policies), mapAdvisors(advisors)),
      // B7 + Site URL. fetchAuthConfig returns null when the request fails, and
      // scanAuthConfig treats null as "we learned nothing" rather than as a
      // clean bill of health — a failed fetch must never look like a pass.
      ...scanAuthConfig(authConfig),
      // B1/B2/B4/B5/B11 — same config object, no extra request.
      ...scanAuthPolicy(authConfig),
      // A5 — column grants to anon/authenticated. The bug we shipped ourselves.
      ...analyzeGrants(await fetchColumnGrants(token.accessToken, projectRef)),
      // A8/A15/A16/A17 — what the database itself can reach.
      ...scanExtensions(await fetchDatabaseCapabilities(token.accessToken, projectRef)),
      // A12/A13 storage, A19 recovery posture.
      ...scanStorage(await fetchStorageConfig(token.accessToken, projectRef)),
      ...checkBackups(await fetchBackupConfig(token.accessToken, projectRef)),
      // A14 Realtime authorisation, A20 auth-hook claim integrity.
      ...scanRealtimeAndHooks(await fetchRealtimeAndHooks(token.accessToken, projectRef)),
    ];

    // Feed the graph's database collector with the raw facts, not our verdicts.
    // The reasoner combines them with route facts to produce paths neither
    // source can see alone.
    await saveFacts(userId, "db", { policies, advisors, authConfig }, { merge: true });

    // A21 exposure inventory. SCHEMA ONLY — column names and row counts, never
    // a value. Best-effort: a project we cannot enumerate simply has no
    // inventory, which the model reports as "we don't know" rather than zero.
    try {
      const columns = await fetchSchemaColumns(token.accessToken, projectRef);
      const tables = [...new Set(columns.map((c) => c.table))];
      const rowCounts = await fetchRowCounts(token.accessToken, projectRef, tables);
      await saveFacts(
        userId,
        "db",
        { inventory: buildInventory(columns, rowCounts) },
        { merge: true }
      );
    } catch (err) {
      console.error(
        "[supabaseMgmt] schema inventory failed:",
        err instanceof Error ? err.message : err
      );
    }

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
        for (const t of buildTableFacts({ policies, advisors }).values()) {
          if (t.permissivePolicy || t.rlsEnabled === false) suspected.add(t.qualified);
        }

        const schema = new Map<string, string[]>();
        for (const c of await fetchSchemaColumns(token.accessToken, projectRef)) {
          schema.set(c.table, [...(schema.get(c.table) ?? []), c.column]);
        }

        const result = await runProvingGround(
          userId,
          token.accessToken,
          projectRef,
          settings,
          [...suspected],
          schema
        );
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
    try {
      await runAuthLogScan(userId, await fetchAuthAuditLog(token.accessToken, projectRef));
    } catch (err) {
      console.error("[supabaseMgmt] auth log scan failed:", err instanceof Error ? err.message : err);
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
    console.error(
      "[supabaseMgmt] policy scan failed:",
      err instanceof Error ? err.message : err
    );
    return { ok: false, findings: 0, reason: "scan_failed" };
  }

  // Same persistence shape as lib/deep/githubRun.ts: insert only findings that
  // aren't already active, and archive the ones that have since been fixed.
  // deep_findings has no unique constraint on (user_id, finding_id), so this is
  // read-then-write rather than an upsert. Everything downstream (fix lanes,
  // agent brief, MCP, the dashboard) picks these up unchanged.
  const nowIso = new Date().toISOString();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "policy")
    .is("archived_at", null);

  const activeIds = new Set((existing ?? []).map((r) => r.finding_id as string));
  const currentIds = new Set(findings.map((f) => f.id));

  // Resolved: was active, isn't any more.
  const resolved = [...activeIds].filter((id) => !currentIds.has(id));
  if (resolved.length > 0) {
    await admin
      .from("deep_findings")
      .update({ archived_at: nowIso })
      .eq("user_id", userId)
      .eq("source", "policy")
      .is("archived_at", null)
      .in("finding_id", resolved);
  }

  const fresh = findings.filter((f) => !activeIds.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "policy",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: f.consequence,
        package_name: f.packageName,
        version: f.version,
        vuln_id: f.vulnId,
        cve_id: f.cveId,
      }))
    );
  }

  return { ok: true, findings: findings.length };
}
