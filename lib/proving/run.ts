import { getSupabaseAdmin } from "@/lib/supabase";
import { createProvingBranch, deleteProvingBranch, runOnBranch } from "./branch";
import { canProve, type CustomerAutonomySettings } from "./guard";
import {
  buildProbeSql,
  buildSeedSql,
  interpretProbe,
  selectTablesToProbe,
  type ProbeOutcome,
  type ProvenFinding,
} from "./tenantProbe";

// Orchestration for the proving ground.
//
// Two properties matter more than anything else here and both are structural:
//
//   1. THE BRANCH IS ALWAYS TORN DOWN. Every path out of this function goes
//      through a finally block. A leaked branch bills the customer indefinitely
//      for something they cannot see and did not ask for — a worse outcome than
//      never running the probe.
//   2. NOTHING RUNS WITHOUT OPT-IN AND WITH THE KILL SWITCH ON. Checked before a
//      branch is created (so we do not spend their money), and again inside
//      runOnBranch before every statement.

export interface ProvingResult {
  ran: boolean;
  reason?: string;
  findings: ProvenFinding[];
  probed: number;
}

export async function runProvingGround(
  userId: string,
  accessToken: string,
  productionRef: string,
  settings: CustomerAutonomySettings,
  suspectedTables: string[],
  schema: Map<string, string[]>
): Promise<ProvingResult> {
  // Cheapest refusals first: never spend a customer's money to discover we were
  // not allowed to.
  if (settings.killSwitchOn) return { ran: false, reason: "kill_switch", findings: [], probed: 0 };
  if (!settings.provingGroundEnabled) return { ran: false, reason: "not_enabled", findings: [], probed: 0 };

  const targets = selectTablesToProbe(suspectedTables, schema);
  // Nothing the reasoner suspects means nothing to prove. Standing up a branch
  // to test nothing would be pure cost.
  if (targets.length === 0) return { ran: false, reason: "nothing_to_probe", findings: [], probed: 0 };

  const handle = await createProvingBranch(accessToken, productionRef);
  if (!handle) return { ran: false, reason: "branch_unavailable", findings: [], probed: 0 };

  const findings: ProvenFinding[] = [];
  let probed = 0;

  try {
    if (!canProve(handle.target, settings)) {
      return { ran: false, reason: "guard_refused", findings: [], probed: 0 };
    }

    for (const { table, ownerColumn } of targets) {
      const outcome: ProbeOutcome = { table, ownerColumn, leakedRows: 0, executed: false };
      try {
        await runOnBranch(accessToken, handle, settings, buildSeedSql(table, ownerColumn).sql);
        const rows = await runOnBranch<{ leaked: number }>(
          accessToken,
          handle,
          settings,
          buildProbeSql(table, ownerColumn)
        );
        outcome.leakedRows = Number(rows[0]?.leaked ?? 0);
        outcome.executed = true;
        probed++;
      } catch (err) {
        // A table we could not seed or query cleanly yields no conclusion. We
        // would rather skip it than report a result we do not understand.
        outcome.skippedReason = err instanceof Error ? err.message : "probe failed";
      }
      const finding = interpretProbe(outcome);
      if (finding) findings.push(finding);
    }
  } finally {
    // Always. Even on an unexpected throw, even if the guard refused.
    await deleteProvingBranch(accessToken, handle.ref);
  }

  await persistProvenFindings(userId, findings, probed);
  return { ran: true, findings, probed };
}

/**
 * Persists proven findings.
 *
 * Only archives when at least one table was actually probed. A run that proved
 * nothing because the branch would not come up must not close a previously
 * PROVEN finding — that would replace evidence with an absence of evidence.
 */
export async function persistProvenFindings(
  userId: string,
  findings: ProvenFinding[],
  probed: number
): Promise<{ newCount: number; resolvedCount: number }> {
  const admin = getSupabaseAdmin();

  const { data: existing } = await admin
    .from("deep_findings")
    .select("finding_id")
    .eq("user_id", userId)
    .eq("source", "proven")
    .is("archived_at", null);

  const active = new Set((existing ?? []).map((r) => r.finding_id as string));
  const current = new Set(findings.map((f) => f.id));

  let resolvedCount = 0;
  if (probed > 0) {
    const resolved = [...active].filter((id) => !current.has(id));
    if (resolved.length > 0) {
      await admin
        .from("deep_findings")
        .update({ archived_at: new Date().toISOString() })
        .eq("user_id", userId)
        .eq("source", "proven")
        .is("archived_at", null)
        .in("finding_id", resolved);
      resolvedCount = resolved.length;
    }
  }

  const fresh = findings.filter((f) => !active.has(f.id));
  if (fresh.length > 0) {
    await admin.from("deep_findings").insert(
      fresh.map((f) => ({
        user_id: userId,
        source: "proven",
        finding_id: f.id,
        severity: f.severity,
        title: f.title,
        consequence: f.consequence,
      }))
    );
  }

  return { newCount: fresh.length, resolvedCount };
}
