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
} from "./supabaseMgmt";
import { analyzePolicies, mapAdvisors, mergePolicyFindings } from "./policyScan";

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
      "supabase_mgmt_token_encrypted, supabase_mgmt_refresh_encrypted, supabase_mgmt_expires_at, supabase_mgmt_project_ref"
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
    const [policies, advisors] = await Promise.all([
      fetchPolicies(token.accessToken, projectRef),
      fetchAdvisors(token.accessToken, projectRef),
    ]);
    findings = mergePolicyFindings(analyzePolicies(policies), mapAdvisors(advisors));
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
